package easypatch

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// A job in full, for a technician (ADR-0030, amended 2026-11-22): besides
// what the engine keeps of the job, the device it ran on as EasyRMM and the
// engine know it; how it started, from EasyRMM's audit trail; and what the
// engine knows of each of its updates on that device. The engine keeps no
// output of a patch job, so there is none to show.

// originSlack is how much earlier than the engine's clock says a job was
// created its audit record may be: the two clocks may differ.
const originSlack = time.Hour

// JobDevice is the device a job ran on.
type JobDevice struct {
	OrganizationName string `json:"organizationName"`
	SiteName         string `json:"siteName"`
	Platform         string `json:"platform"`
	// OS is the operating system as EasyRMM's agent reported it;
	// AgentVersion, that agent's version (nil without one).
	OS           string  `json:"os"`
	AgentVersion *string `json:"agentVersion"`
	// Endpoint is the device as the engine knows it; nil when the engine
	// could not be read.
	Endpoint *JobEndpoint `json:"endpoint"`
}

// JobEndpoint is a job's endpoint as the engine knows it.
type JobEndpoint struct {
	Hostname        string `json:"hostname"`
	OperatingSystem string `json:"operatingSystem"`
	OSBuild         string `json:"osBuild"`
	// OSSupportStatus is Supported, ExtendedSecurityUpdates, Unsupported or
	// Unknown.
	OSSupportStatus string `json:"osSupportStatus"`
	// AgentVersion is the EasyPatch agent's.
	AgentVersion  string     `json:"agentVersion"`
	AgentOutdated bool       `json:"agentOutdated"`
	Online        bool       `json:"online"`
	LastCheckInAt *time.Time `json:"lastCheckInAt"`
	RebootPending bool       `json:"rebootPending"`
}

// JobOrigin is how EasyRMM started a job, from its audit record.
type JobOrigin struct {
	// Action is the record's: patch.install, patch.scan, patch.restart,
	// patch.retry, patch.remove_update...
	Action string `json:"action"`
	// By is who asked: a user's email, or EasyRMM's component when System
	// (a restart after an install).
	By     string    `json:"by"`
	System bool      `json:"system"`
	At     time.Time `json:"at"`
	// PatchAll is the organization or site of the Patch all the job was
	// part of; RequestID, the request its devices' jobs share.
	PatchAll  *string `json:"patchAll"`
	RequestID *string `json:"requestId"`
	// Updates is what an install installed: "all eligible", "all
	// available", or how many it chose.
	Updates         *string `json:"updates"`
	FeatureUpgrades *bool   `json:"featureUpgrades"`
	ScheduledAt     *string `json:"scheduledAt"`
}

// UpdateFacts is what the engine knows of one of a job's updates on its
// device.
type UpdateFacts struct {
	KbNumbers      []string   `json:"kbNumbers"`
	MsrcSeverity   string     `json:"msrcSeverity"`
	SizeBytes      *int64     `json:"sizeBytes"`
	ReleaseDate    *time.Time `json:"releaseDate"`
	CveIDs         []string   `json:"cveIds"`
	KnownExploited bool       `json:"knownExploited"`
	KevDueDate     string     `json:"kevDueDate"`
	SupportURL     string     `json:"supportUrl"`
	// State is the update's on the device now: Installed, Missing, Failed...
	State   string   `json:"state"`
	Package *Package `json:"package"`
}

// jobView adds to a job what a technician needs beside it.
func (s *Service) jobView(ctx context.Context, c access.Caller, cl *Client, j JobDetail, d deviceRow) (JobDetailView, error) {
	j.Items, j.Events = orEmpty(j.Items), orEmpty(j.Events)
	v := JobDetailView{JobDetail: j, DeviceID: d.id, DeviceName: d.name, CanManage: c.Can(rbac.PermPatchManage, d.resource()),
		Device: JobDevice{OrganizationName: d.organizationName, SiteName: d.siteName, Platform: d.platform}, UpdateFacts: map[uuid.UUID]UpdateFacts{}}
	var err error
	if v.RestartAfter, v.RestartFor, err = s.restartAfter(ctx, c, j.Summary.ID); err != nil {
		return JobDetailView{}, err
	}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT os_description, agent_version FROM devices WHERE id = $1`, d.id).Scan(&v.Device.OS, &v.Device.AgentVersion)
	})
	if err != nil {
		return JobDetailView{}, err
	}
	if v.Origin, err = s.origin(ctx, d.id, j.Summary); err != nil {
		return JobDetailView{}, err
	}
	rctx := s.as(ctx, c, RoleReadOnly, orgOf(d)...)
	var wg sync.WaitGroup
	wg.Go(func() {
		e, err := cl.Endpoint(rctx, j.Summary.EndpointID)
		if err != nil {
			s.noteError(err)
			return
		}
		v.Device.Endpoint = &JobEndpoint{Hostname: e.Summary.Hostname, OperatingSystem: e.Summary.OperatingSystem, OSBuild: e.Summary.OSBuild,
			OSSupportStatus: e.Summary.OSSupportStatus, AgentVersion: e.Summary.AgentVersion, AgentOutdated: e.Summary.AgentOutdated,
			Online: e.Summary.IsOnline, LastCheckInAt: e.Summary.LastCheckInAt, RebootPending: e.Summary.RebootPending}
	})
	if len(j.Items) > 0 {
		v.UpdateFacts, v.UpdateFactsError = s.updateFacts(rctx, cl, j)
	}
	wg.Wait()
	return v, nil
}

// updateFacts reads what the engine knows of a job's updates on its
// endpoint, from its lists of updates installed and still to install; an
// update on neither is no longer offered to it.
func (s *Service) updateFacts(ctx context.Context, cl *Client, j JobDetail) (map[uuid.UUID]UpdateFacts, *string) {
	want := map[uuid.UUID]bool{}
	for _, it := range j.Items {
		want[it.UpdateGUID] = true
	}
	var missing, installed []Update
	var errMissing, errInstalled error
	var wg sync.WaitGroup
	wg.Go(func() { missing, errMissing = cl.Updates(ctx, j.Summary.EndpointID, "") })
	wg.Go(func() { installed, errInstalled = cl.InstalledUpdates(ctx, j.Summary.EndpointID) })
	wg.Wait()
	out := map[uuid.UUID]UpdateFacts{}
	// An update both installed and offered again is shown as offered.
	for _, list := range [][]Update{installed, missing} {
		for _, u := range list {
			if want[u.UpdateGUID] {
				out[u.UpdateGUID] = UpdateFacts{KbNumbers: orEmpty(u.KbNumbers), MsrcSeverity: u.MsrcSeverity, SizeBytes: u.SizeBytes,
					ReleaseDate: u.ReleaseDate, CveIDs: orEmpty(u.CveIDs), KnownExploited: u.KnownExploited, KevDueDate: u.KevDueDate,
					SupportURL: u.SupportURL, State: u.State, Package: u.Package}
			}
		}
	}
	if err := errors.Join(errMissing, errInstalled); err != nil {
		s.noteError(err)
		msg := cut(message(epError(err)), 300)
		return out, &msg
	}
	return out, nil
}

// origin reads how EasyRMM started a job, from the audit record that names
// it: nil when EasyRMM did not start it (a policy, a schedule or the engine
// did) or the record is gone. A cancellation names the job too, but never
// started it.
func (s *Service) origin(ctx context.Context, device uuid.UUID, j Job) (*JobOrigin, error) {
	var o JobOrigin
	var details map[string]any
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT action, actor_label, actor_type = 'system', occurred_at, details FROM audit_log
			WHERE device_id = $1 AND occurred_at >= $2 AND action LIKE 'patch.%' AND action <> 'patch.cancel' AND details->>'jobId' = $3
			ORDER BY occurred_at LIMIT 1`, device, j.CreatedAt.Add(-originSlack), j.ID.String()).Scan(&o.Action, &o.By, &o.System, &o.At, &details)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}
	text := func(k string) *string {
		var t string
		switch x := details[k].(type) {
		case string:
			t = x
		case float64:
			t = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			return nil
		}
		return &t
	}
	o.PatchAll, o.RequestID, o.Updates, o.ScheduledAt = text("patchAll"), text("requestId"), text("updates"), text("scheduledAt")
	if b, ok := details["featureUpgrades"].(bool); ok {
		o.FeatureUpgrades = &b
	}
	return &o, nil
}
