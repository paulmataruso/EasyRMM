package easypatch

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// A device's Patches tab beyond scans, installs and restarts: exclusions, the
// install preview, removing an update, messages to users and agent updates.
// Each is checked against EasyRMM's permissions on the device first and then
// sent with a statement naming the caller, the role the call needs and the
// device's organization only (ADR-0038). Acting needs patch.manage on the
// device: none of these edit a policy.

// maxReason is the longest reason EasyPatch keeps.
const maxReason = 500

// ExclusionInput keeps an update off a device.
type ExclusionInput struct {
	UpdateID uuid.UUID `json:"updateId"`
	Reason   string    `json:"reason"`
}

// manageable reads a linked device the caller may manage patching of, and
// a client that may act.
func (s *Service) manageable(ctx context.Context, c access.Caller, id uuid.UUID) (deviceRow, *Client, error) {
	d, _, cl, err := s.linked(ctx, c, id, rbac.PermPatchManage)
	if err != nil {
		return d, nil, err
	}
	return d, cl, nil
}

func (s *Service) deviceEvent(c access.Caller, d deviceRow, action string, details map[string]any) audit.Event {
	det := map[string]any{"device": d.name, "endpointId": d.endpointID.String()}
	for k, v := range details {
		det[k] = v
	}
	return audit.Event{Actor: c.Actor, Action: action, OrganizationID: d.organizationID, SiteID: d.siteID, DeviceID: d.id,
		TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success, Details: det}
}

// Exclude keeps an update off a device: EasyPatch does not install it there,
// automatically or when asked for every update, and it no longer counts
// against the device's compliance.
func (s *Service) Exclude(ctx context.Context, c access.Caller, deviceID uuid.UUID, in ExclusionInput) error {
	in.Reason = strings.TrimSpace(in.Reason)
	f := apperr.Fields{}
	f.Check(in.UpdateID != uuid.Nil, "updateId", "Choose an update.")
	f.Check(len([]rune(in.Reason)) <= maxReason, "reason", "Keep the reason under 500 characters.")
	if err := f.Err(); err != nil {
		return err
	}
	d, cl, err := s.manageable(ctx, c, deviceID)
	if err != nil {
		return err
	}
	if err := cl.Exclude(s.as(ctx, c, RoleAdmin, orgOf(d)...), *d.endpointID, in.UpdateID, in.Reason, c.Actor.Label); err != nil {
		return epError(err)
	}
	s.fleet.clear()
	det := map[string]any{"updateId": in.UpdateID.String()}
	if in.Reason != "" {
		det["reason"] = in.Reason
	}
	return s.record(ctx, []audit.Event{s.deviceEvent(c, d, "patch.exclude", det)})
}

// Include lets EasyPatch install an excluded update on a device again.
func (s *Service) Include(ctx context.Context, c access.Caller, deviceID, updateID uuid.UUID) error {
	d, cl, err := s.manageable(ctx, c, deviceID)
	if err != nil {
		return err
	}
	if err := cl.Include(s.as(ctx, c, RoleAdmin, orgOf(d)...), *d.endpointID, updateID, c.Actor.Label); err != nil {
		return epError(err)
	}
	s.fleet.clear()
	return s.record(ctx, []audit.Event{s.deviceEvent(c, d, "patch.include", map[string]any{"updateId": updateID.String()})})
}

// InstallPreview says what installing on a device would do: every update its
// policy allows when updateIDs is empty, those otherwise.
func (s *Service) InstallPreview(ctx context.Context, c access.Caller, deviceID uuid.UUID, updateIDs []uuid.UUID) (InstallPreview, error) {
	if len(updateIDs) > 1000 {
		return InstallPreview{}, apperr.Invalid("updateIds", "Choose at most 1,000 updates.")
	}
	d, _, cl, err := s.linked(ctx, c, deviceID, rbac.PermPatchView)
	if err != nil {
		return InstallPreview{}, err
	}
	p, err := cl.InstallPreview(s.as(ctx, c, RoleReadOnly, orgOf(d)...), *d.endpointID, updateIDs)
	if err != nil {
		return p, epError(err)
	}
	p.Items, p.Skipped, p.Warnings = orEmpty(p.Items), orEmpty(p.Skipped), orEmpty(p.Warnings)
	return p, nil
}

// RemoveInput removes an installed update from a device.
type RemoveInput struct {
	// Block also excludes the update, so that EasyPatch does not install
	// it again.
	Block  bool   `json:"block"`
	Reason string `json:"reason"`
}

// RemoveUpdate has a device uninstall an installed Windows update. The agent
// never restarts the computer for it; a removal that needs a restart waits
// for the next one.
func (s *Service) RemoveUpdate(ctx context.Context, c access.Caller, deviceID, updateID uuid.UUID, in RemoveInput) (ActionResult, error) {
	in.Reason = strings.TrimSpace(in.Reason)
	if len([]rune(in.Reason)) > maxReason {
		return ActionResult{}, apperr.Invalid("reason", "Keep the reason under 500 characters.")
	}
	d, cl, err := s.manageable(ctx, c, deviceID)
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}}
	j, err := cl.RemoveUpdate(s.as(ctx, c, RoleAdmin, orgOf(d)...), *d.endpointID, updateID, in.Block, in.Reason, c.Actor.Label)
	if err != nil {
		// EasyPatch refuses what the device cannot do (a Linux package, an
		// agent before 1.8.0, an update another job is working on): said
		// as the device's outcome, like a bulk action's.
		if IsStatus(err, http.StatusBadRequest) || IsStatus(err, http.StatusConflict) || IsStatus(err, http.StatusUnprocessableEntity) {
			res.add(ActionItem{DeviceID: d.id, DeviceName: d.name, Message: message(epError(err))})
			return res, nil
		}
		return ActionResult{}, epError(err)
	}
	res.add(ActionItem{DeviceID: d.id, DeviceName: d.name, OK: true, JobID: &j.ID})
	s.fleet.clear()
	det := map[string]any{"updateId": updateID.String(), "jobId": j.ID.String(), "block": in.Block}
	if in.Reason != "" {
		det["reason"] = in.Reason
	}
	return res, s.record(ctx, []audit.Event{s.deviceEvent(c, d, "patch.remove_update", det)})
}

// The messages EasyPatch can show; there is no free text.
var messagePresets = []string{"UpdatesInstalling", "UpdatesInstalled", "RestartRequired", "SaveYourWork", "MaintenanceTonight", "RestartScheduled"}

// MessagePresets lists the messages EasyPatch can show to users.
func (s *Service) MessagePresets(ctx context.Context, c access.Caller) ([]MessagePreset, error) {
	if !c.CanAnywhere(rbac.PermPatchView) {
		return nil, apperr.Forbidden()
	}
	r, cl, err := s.conn(ctx)
	switch {
	case err != nil:
		return nil, err
	case r == nil:
		return nil, errNotConfigured
	}
	list, err := cl.MessagePresets(s.as(ctx, c, RoleReadOnly))
	if err != nil {
		return nil, epError(err)
	}
	return orEmpty(list), nil
}

// NotifyInput shows a message to the users of devices.
type NotifyInput struct {
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	Preset    string      `json:"preset"`
	// RestartAt is the time RestartScheduled names.
	RestartAt *time.Time `json:"restartAt"`
}

// Notify shows a preset message to the users signed in to devices, through
// the EasyPatch tray. Devices whose agent has no tray are reported, not sent.
func (s *Service) Notify(ctx context.Context, c access.Caller, in NotifyInput) (ActionResult, error) {
	f := apperr.Fields{}
	f.Check(slices.Contains(messagePresets, in.Preset), "preset", "Choose a message.")
	if in.Preset == "RestartScheduled" {
		switch {
		case in.RestartAt == nil:
			f.Add("restartAt", "Choose the restart time the message names.")
		case in.RestartAt.Before(s.now()):
			f.Add("restartAt", "Choose a time in the future.")
		case in.RestartAt.After(s.now().Add(maxScheduleAhead)):
			f.Add("restartAt", "Choose a time within 31 days.")
		}
	} else {
		in.RestartAt = nil
	}
	if err := f.Err(); err != nil {
		return ActionResult{}, err
	}
	_, cl, err := s.operable(ctx)
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}}
	devices, err := s.targets(ctx, c, in.DeviceIDs, &res)
	if err != nil {
		return ActionResult{}, err
	}
	m := Message{Preset: in.Preset}
	details := map[string]any{"message": in.Preset}
	if in.RestartAt != nil {
		at := in.RestartAt.UTC()
		m.RestartAt = &at
		details["restartAt"] = at.Format(time.RFC3339)
	}
	actx := s.as(ctx, c, RoleAdmin, orgsOf(devices)...)
	err = s.bulk(ctx, c, devices, &res, "patch.notify", details, func(ids []uuid.UUID) (BulkResult, error) {
		return cl.BulkNotify(actx, ids, m, c.Actor.Label)
	})
	return res, err
}

// UpdateAgent has devices' EasyPatch agents update themselves to the newest
// package EasyPatch hosts whose release signature they accept.
func (s *Service) UpdateAgent(ctx context.Context, c access.Caller, in ActionInput) (ActionResult, error) {
	if len(in.UpdateIDs) > 0 || in.ScheduledAt != nil {
		return ActionResult{}, apperr.Invalid("deviceIds", "Updating the EasyPatch agent takes devices only.")
	}
	_, cl, err := s.operable(ctx)
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}}
	devices, err := s.targets(ctx, c, in.DeviceIDs, &res)
	if err != nil {
		return ActionResult{}, err
	}
	actx := s.as(ctx, c, RoleAdmin, orgsOf(devices)...)
	err = s.bulk(ctx, c, devices, &res, "patch.agent_update", nil, func(ids []uuid.UUID) (BulkResult, error) {
		return cl.BulkAgentUpdate(actx, ids, c.Actor.Label)
	})
	s.fleet.clear()
	return res, err
}
