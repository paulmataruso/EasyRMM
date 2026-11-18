package easypatch

import (
	"context"
	"fmt"
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

// Restarts and retries from EasyRMM (integration plan, P2). A restart is
// always EasyRMM's one preset (restartPreset): only if a restart is still
// pending when the job runs, after EasyPatch's default countdown, now or at a
// chosen time. Servers are restarted only when the person confirmed each one
// by name. Everything else about restarts stays in EasyPatch's console.

// RestartCheck is what a restart would do to one device.
type RestartCheck struct {
	DeviceID   uuid.UUID `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	// Restart says the device would be restarted; Reason says why not.
	Restart bool   `json:"restart"`
	Reason  string `json:"reason,omitempty"`
	// Server says EasyPatch marks the device a server, or cannot tell
	// (EasyPatch before 1.10.0): it is restarted only when confirmed.
	Server bool `json:"server"`
	Online bool `json:"online"`
}

// RestartPlan is what a restart of chosen devices would do.
type RestartPlan struct {
	Devices []RestartCheck `json:"devices"`
	// ServersKnown is false when EasyPatch cannot tell servers apart, so
	// every device is treated as one.
	ServersKnown bool `json:"serversKnown"`
}

// restartTarget is a linked device a restart could go to, and its check
// in the plan (an index: the plan's list grows while targets are found).
type restartTarget struct {
	device deviceRow
	check  int
}

// PlanRestart says what a restart of the devices would do, without doing it.
func (s *Service) PlanRestart(ctx context.Context, c access.Caller, ids []uuid.UUID) (RestartPlan, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return RestartPlan{}, err
	}
	plan, _, err := s.planRestart(ctx, c, cl, ids)
	return plan, err
}

func (s *Service) planRestart(ctx context.Context, c access.Caller, cl *Client, ids []uuid.UUID) (RestartPlan, []restartTarget, error) {
	if len(ids) == 0 || len(ids) > MaxBulk {
		return RestartPlan{}, nil, apperr.Invalid("deviceIds", fmt.Sprintf("Choose from 1 to %d devices.", MaxBulk))
	}
	plan := RestartPlan{Devices: []RestartCheck{}, ServersKnown: true}
	var targets []restartTarget
	byOrg := map[uuid.UUID][]int{} // EasyPatch organization → indexes into targets
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		d, err := s.device(ctx, c, id, rbac.PermPatchManage)
		if err != nil {
			return RestartPlan{}, nil, err
		}
		check := RestartCheck{DeviceID: d.id, DeviceName: d.name}
		if err := notLinked(d); err != nil {
			check.Reason = message(err)
		} else if d.easyPatchOrg == nil {
			check.Reason = "Its organization is not linked to EasyPatch."
		}
		plan.Devices = append(plan.Devices, check)
		if check.Reason == "" {
			byOrg[*d.easyPatchOrg] = append(byOrg[*d.easyPatchOrg], len(targets))
			targets = append(targets, restartTarget{device: d, check: len(plan.Devices) - 1})
		}
	}
	for org, idx := range byOrg {
		pending, err := cl.RestartPending(ctx, org)
		switch {
		case IsStatus(err, http.StatusNotFound):
			// EasyPatch before 1.10.0: read the pending restart off its
			// endpoint list, and treat every device as a server.
			plan.ServersKnown = false
			endpoints, err := s.endpoints(ctx, cl, org)
			if err != nil {
				s.noteError(ctx, err)
				return RestartPlan{}, nil, epError(err)
			}
			for _, i := range idx {
				t := targets[i]
				check := &plan.Devices[t.check]
				e, ok := endpoints[*t.device.endpointID]
				switch {
				case !ok:
					check.Reason = "EasyPatch no longer lists its endpoint."
				case !e.RebootPending:
					check.Reason = "No restart is pending."
				default:
					check.Restart, check.Server, check.Online = true, true, e.IsOnline
				}
			}
		case err != nil:
			s.noteError(ctx, err)
			return RestartPlan{}, nil, epError(err)
		default:
			listed := map[uuid.UUID]PendingRestart{}
			for _, e := range pending.Endpoints {
				listed[e.ID] = e
			}
			for _, i := range idx {
				t := targets[i]
				check := &plan.Devices[t.check]
				e, ok := listed[*t.device.endpointID]
				switch {
				case !ok && pending.Total > len(pending.Endpoints):
					check.Reason = "EasyPatch lists only the first 1,000 restarts pending in this organization; restart it in EasyPatch."
				case !ok:
					check.Reason = "No restart is pending."
				case !e.CanRestart:
					check.Reason = "Its EasyPatch agent cannot restart the computer; update the agent first."
				default:
					check.Restart, check.Server, check.Online = true, e.IsServer, e.IsOnline
				}
			}
		}
	}
	return plan, targets, nil
}

// RestartInput chooses the devices of a restart.
type RestartInput struct {
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	// ScheduledAt restarts at that time rather than now.
	ScheduledAt *time.Time `json:"scheduledAt"`
	// ConfirmServers lists the servers the person confirmed restarting.
	ConfirmServers []uuid.UUID `json:"confirmServers"`
}

// Restart restarts the devices that have a restart pending, with EasyRMM's
// preset. A server not confirmed in ConfirmServers stops the whole request.
func (s *Service) Restart(ctx context.Context, c access.Caller, in RestartInput) (ActionResult, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return ActionResult{}, err
	}
	if in.ScheduledAt != nil {
		now := s.now()
		switch {
		case in.ScheduledAt.Before(now.Add(time.Minute)):
			return ActionResult{}, apperr.Invalid("scheduledAt", "Choose a time in the future.")
		case in.ScheduledAt.After(now.Add(maxScheduleAhead)):
			return ActionResult{}, apperr.Invalid("scheduledAt", "Choose a time within 31 days.")
		}
		at := in.ScheduledAt.UTC()
		in.ScheduledAt = &at
	}
	plan, targets, err := s.planRestart(ctx, c, cl, in.DeviceIDs)
	if err != nil {
		return ActionResult{}, err
	}
	var unconfirmed, servers []string
	for _, t := range targets {
		if check := plan.Devices[t.check]; check.Restart && check.Server {
			if !slices.Contains(in.ConfirmServers, t.device.id) {
				unconfirmed = append(unconfirmed, t.device.name)
			}
			servers = append(servers, t.device.name)
		}
	}
	if len(unconfirmed) > 0 {
		what := "These are servers"
		if !plan.ServersKnown {
			what = "EasyPatch cannot say which of these are servers"
		}
		return ActionResult{}, apperr.Invalid("confirmServers", what+"; confirm restarting them: "+strings.Join(unconfirmed, ", ")+".")
	}
	res := ActionResult{Results: []ActionItem{}}
	var devices []deviceRow
	for _, ch := range plan.Devices {
		if !ch.Restart {
			res.add(ActionItem{DeviceID: ch.DeviceID, DeviceName: ch.DeviceName, Message: ch.Reason})
		}
	}
	for _, t := range targets {
		if plan.Devices[t.check].Restart {
			devices = append(devices, t.device)
		}
	}
	details := map[string]any{"condition": "only if a restart is pending"}
	if in.ScheduledAt != nil {
		details["scheduledAt"] = in.ScheduledAt.Format(time.RFC3339)
	}
	if len(servers) > 0 {
		details["confirmedServers"] = servers
	}
	err = s.bulk(ctx, c, devices, &res, "patch.restart", details, func(ids []uuid.UUID) (BulkResult, error) {
		return cl.BulkRestart(ctx, ids, in.ScheduledAt, c.Actor.Label)
	})
	s.fleet.clear()
	return res, err
}

// RetryJob runs a finished job of a device the caller may manage patching
// of again, as a new job, which it returns.
func (s *Service) RetryJob(ctx context.Context, c access.Caller, id uuid.UUID) (JobView, error) {
	old, d, r, cl, err := s.job(ctx, c, id)
	if err != nil {
		return JobView{}, err
	}
	if !c.Can(rbac.PermPatchManage, d.resource()) {
		return JobView{}, apperr.Forbidden()
	}
	if !r.canOperate {
		return JobView{}, errReadOnly
	}
	j, err := cl.RetryJob(ctx, id, c.Actor.Label)
	if err != nil {
		return JobView{}, epError(err)
	}
	if err := s.audit.Record(ctx, audit.Event{Actor: c.Actor, Action: "patch.retry", OrganizationID: d.organizationID, SiteID: d.siteID,
		DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success,
		Details: map[string]any{"device": d.name, "jobId": j.ID.String(), "retryOf": id.String(), "jobType": old.Summary.Type}}); err != nil {
		return JobView{}, err
	}
	s.fleet.clear()
	return JobView{Job: j, DeviceID: d.id, DeviceName: d.name, CanManage: true}, nil
}
