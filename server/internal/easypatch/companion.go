package easypatch

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
)

// Repairs and log collection through the patching engine (ADR-0069, Part
// R): when the EasyRMM agent is silent while the EasyPatch agent checks in,
// the engine's RepairCompanion job has the EasyPatch agent restart the
// EasyRMM agent or repair it from its recovery copy, and CollectLogs returns
// the newest lines of the three agents' logs. A job names a target and a
// step from fixed lists and, for a repair, the SHA-256 EasyRMM recorded for
// the device's build (devices.agent_sha256); the engine sends it only to an
// agent that declares the capability.

// companionActor names who the engine's audit trail says asked.
const companionActor = "EasyRMM recovery"

// linkedEndpoint is the engine endpoint of a device whose EasyPatch agent is
// linked, and why there is none or why it must be left alone ("" when it can
// be used).
func (s *Service) linkedEndpoint(ctx context.Context, deviceID uuid.UUID) (endpoint uuid.UUID, why string, err error) {
	var leaving bool
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT e.endpoint_id, `+devices.LeavingSQL+`
			FROM easypatch_devices e JOIN devices d ON d.id = e.device_id
			WHERE e.device_id = $1 AND e.state = 'linked' AND e.endpoint_id IS NOT NULL`, deviceID).Scan(&endpoint, &leaving)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return uuid.Nil, "This device has no EasyPatch agent that is linked to it.", nil
	case err != nil:
		return uuid.Nil, "", err
	case leaving:
		return uuid.Nil, "The device is leaving.", nil
	}
	return endpoint, "", nil
}

// StartCompanion has the device's EasyPatch agent carry out one step on the
// EasyRMM agent or MeshAgent: target and step as agentproto names them, and
// for the EasyRMM agent's repair the hash its recovery copy must have. It
// returns the engine's job. why says what stops it for good (no linked
// agent, an agent too old, a step the engine refuses); err is an engine that
// could not be reached, which is tried again.
func (s *Service) StartCompanion(ctx context.Context, deviceID uuid.UUID, target, step, expectedSHA256 string) (jobID, why string, err error) {
	return s.startJob(ctx, deviceID, func(cl *Client, endpoint uuid.UUID) (Job, error) {
		return cl.RepairCompanion(ctx, endpoint, target, step, expectedSHA256, companionActor)
	})
}

// CollectLogs has the device's EasyPatch agent return the newest lines of
// the three agents' logs; CompanionResult reads them back.
func (s *Service) CollectLogs(ctx context.Context, deviceID uuid.UUID) (jobID, why string, err error) {
	return s.startJob(ctx, deviceID, func(cl *Client, endpoint uuid.UUID) (Job, error) {
		return cl.CollectLogs(ctx, endpoint, companionActor)
	})
}

func (s *Service) startJob(ctx context.Context, deviceID uuid.UUID, start func(*Client, uuid.UUID) (Job, error)) (string, string, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		var ae *apperr.Error
		if errors.As(err, &ae) {
			return "", ae.Message, nil
		}
		return "", "", err
	}
	endpoint, why, err := s.linkedEndpoint(ctx, deviceID)
	if err != nil || why != "" {
		return "", why, err
	}
	j, err := start(cl, endpoint)
	if err != nil {
		// What the engine refuses (an agent that cannot, a step it does
		// not know, a job already waiting) is its answer; the rest is an
		// engine that cannot be reached.
		for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusUnprocessableEntity, http.StatusNotFound} {
			if IsStatus(err, status) {
				return "", "The patching engine refused: " + message(epError(err)), nil
			}
		}
		s.noteError(err)
		return "", "", err
	}
	return j.ID.String(), "", nil
}

// CompanionResult says how a job asked for with StartCompanion or
// CollectLogs stands: done when it ended, ok when it did what it was asked,
// the agent's message and its diagnostics (redacted by the agent, at most
// 256 KiB, kept by the engine for 14 days). An engine that cannot be reached
// is an error; the job is read again later.
func (s *Service) CompanionResult(ctx context.Context, jobID string) (done, ok bool, msg, diagnostics string, err error) {
	id, perr := uuid.Parse(jobID)
	if perr != nil {
		return true, false, "The job's identity is not valid.", "", nil //nolint:nilerr // a job that cannot be read ends its step
	}
	_, cl, err := s.operable(ctx)
	if err != nil {
		return false, false, "", "", err
	}
	d, err := cl.Job(ctx, id)
	if IsStatus(err, http.StatusNotFound) {
		return true, false, "The patching engine no longer has the job.", "", nil
	}
	if err != nil {
		s.noteError(err)
		return false, false, "", "", err
	}
	text := strings.TrimSpace(d.Summary.ProgressMessage)
	switch d.Summary.Status {
	case "Completed":
		return true, true, text, d.Diagnostics, nil
	case "Failed":
		if m := strings.TrimSpace(d.Summary.ErrorMessage); m != "" {
			text = m
		}
		if text == "" {
			text = "The EasyPatch agent reported that the step failed."
		}
		return true, false, text, d.Diagnostics, nil
	case statusCanceled:
		return true, false, "The job was canceled.", d.Diagnostics, nil
	case "Expired":
		return true, false, "The EasyPatch agent did not pick the job up in time.", d.Diagnostics, nil
	}
	return false, false, "", "", nil
}

// CancelCompanion cancels a job that did not run in time, so that it does
// not run later, after the repair moved on. It is best effort.
func (s *Service) CancelCompanion(ctx context.Context, jobID string) {
	id, err := uuid.Parse(jobID)
	if err != nil {
		return
	}
	if _, cl, err := s.operable(ctx); err == nil {
		_, _ = cl.CancelJob(ctx, id, companionActor)
	}
}
