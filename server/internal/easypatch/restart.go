package easypatch

import (
	"context"
	"errors"
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

// Restarts and retries from EasyRMM. A restart says how it treats the people
// signed in (a countdown, a prompt with or without a deadline, or at once),
// whether it runs only when a restart is pending when the job runs (the
// default) or always, when it starts and how long it waits for an offline
// computer. Servers are restarted only when the person confirmed each one by
// name.

// maxAlwaysRestart is the most devices a restart that need not be pending
// goes to at once: each is looked up in EasyPatch to tell servers apart.
const maxAlwaysRestart = 100

var (
	restartModes      = []string{"Countdown", "PromptWithDeadline", "PromptNoDeadline", "Immediate"}
	restartConditions = []string{"OnlyIfPending", "Always"}
)

// normalize checks the options as EasyPatch does, fills in the mode and
// condition, and drops minutes the mode does not use.
func (o *RestartOptions) normalize(now time.Time) error {
	if o.Mode == "" {
		o.Mode = "Countdown"
	}
	if o.Condition == "" {
		o.Condition = "OnlyIfPending"
	}
	in := func(n *int, lo, hi int) bool { return n == nil || (*n >= lo && *n <= hi) }
	switch {
	case !slices.Contains(restartModes, o.Mode):
		return apperr.Invalid("mode", "Choose how the people signed in are asked.")
	case !slices.Contains(restartConditions, o.Condition):
		return apperr.Invalid("condition", "Choose whether it restarts only when a restart is pending.")
	case o.Mode == "Countdown" && !in(o.CountdownMinutes, 1, 60):
		return apperr.Invalid("countdownMinutes", "Choose a countdown of 1 to 60 minutes.")
	case o.Mode == "PromptWithDeadline" && !in(o.DeadlineMinutes, 15, 7*24*60):
		return apperr.Invalid("deadlineMinutes", "Choose a deadline from 15 minutes to 7 days.")
	case !in(o.ExpiresAfterMinutes, 15, 24*60):
		return apperr.Invalid("expiresAfterMinutes", "Choose from 15 minutes to 24 hours.")
	}
	if o.Mode != "Countdown" {
		o.CountdownMinutes = nil
	}
	if o.Mode != "PromptWithDeadline" {
		o.DeadlineMinutes = nil
	}
	if o.ScheduledAt != nil {
		switch {
		case o.ScheduledAt.Before(now.Add(time.Minute)):
			return apperr.Invalid("scheduledAt", "Choose a time in the future.")
		case o.ScheduledAt.After(now.Add(maxScheduleAhead)):
			return apperr.Invalid("scheduledAt", "Choose a time within 31 days.")
		}
		at := o.ScheduledAt.UTC()
		o.ScheduledAt = &at
	}
	o.Force = false
	return nil
}

// RestartCheck is what a restart would do to one device.
type RestartCheck struct {
	DeviceID   uuid.UUID `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	// Restart says the device would be restarted; Reason says why not.
	Restart bool   `json:"restart"`
	Reason  string `json:"reason,omitempty"`
	// Server says EasyPatch marks the device a server: it is restarted only
	// when confirmed.
	Server bool `json:"server"`
	Online bool `json:"online"`
}

// RestartPlan is what a restart of chosen devices would do.
type RestartPlan struct {
	Devices []RestartCheck `json:"devices"`
	// Scope is a Patch all's organization or site.
	Scope *ScopeView `json:"scope,omitempty"`
}

// restartTarget is a linked device a restart could go to, and its check
// in the plan (an index: the plan's list grows while targets are found).
type restartTarget struct {
	device deviceRow
	check  int
}

// RestartPlanInput chooses the devices of a restart plan.
type RestartPlanInput struct {
	Targets
	// Condition is OnlyIfPending (the default) or Always.
	Condition string `json:"condition"`
	// AfterInstall plans a restart once an install has finished: each device
	// is read from the engine, whether or not a restart is pending now.
	AfterInstall bool `json:"afterInstall"`
}

// PlanRestart says what a restart of the devices would do, without doing it:
// with condition Always, also on devices with no restart pending.
func (s *Service) PlanRestart(ctx context.Context, c access.Caller, in RestartPlanInput) (RestartPlan, error) {
	if in.Condition != "" && !slices.Contains(restartConditions, in.Condition) {
		return RestartPlan{}, apperr.Invalid("condition", "Choose whether it restarts only when a restart is pending.")
	}
	if err := in.checkTargets(); err != nil {
		return RestartPlan{}, err
	}
	_, cl, err := s.operable(ctx)
	if err != nil {
		return RestartPlan{}, err
	}
	plan, _, err := s.planRestart(ctx, c, cl, in.Targets, in.Condition == conditionAlways, in.AfterInstall)
	return plan, err
}

func (s *Service) planRestart(ctx context.Context, c access.Caller, cl *Client, t Targets, always, afterInstall bool) (RestartPlan, []restartTarget, error) {
	plan := RestartPlan{Devices: []RestartCheck{}}
	var targets []restartTarget
	if t.All {
		sc, err := s.resolveAll(ctx, c, t)
		if err != nil {
			return RestartPlan{}, nil, err
		}
		plan.Scope = &sc.view
		if always && len(sc.devices) > maxAlwaysRestart {
			return RestartPlan{}, nil, apperr.Invalid("condition", fmt.Sprintf("%s has %s devices: restarting whether or not a restart is "+
				"pending reaches at most %d devices at once. Restart only those with a restart pending, or choose devices.",
				sc.view.where(), thousands(len(sc.devices)), maxAlwaysRestart))
		}
		for _, d := range sc.devices {
			plan.Devices = append(plan.Devices, RestartCheck{DeviceID: d.id, DeviceName: d.name})
			targets = append(targets, restartTarget{device: d, check: len(plan.Devices) - 1})
		}
	} else {
		ids := t.DeviceIDs
		if len(ids) == 0 || len(ids) > MaxBulk {
			return RestartPlan{}, nil, apperr.Invalid("deviceIds", fmt.Sprintf("Choose from 1 to %d devices.", MaxBulk))
		}
		if always && len(dedupe(ids)) > maxAlwaysRestart {
			return RestartPlan{}, nil, apperr.Invalid("deviceIds",
				fmt.Sprintf("Choose at most %d devices to restart whether or not a restart is pending.", maxAlwaysRestart))
		}
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
				check.Reason = "Its organization is not in the patching engine yet."
			}
			plan.Devices = append(plan.Devices, check)
			if check.Reason == "" {
				targets = append(targets, restartTarget{device: d, check: len(plan.Devices) - 1})
			}
		}
	}
	if afterInstall {
		// After an install, what is pending now does not matter: each
		// device is read for whether it is a server and can restart.
		if len(targets) > MaxBulk {
			return RestartPlan{}, nil, apperr.Invalid("restart", fmt.Sprintf("Restarting after the install reaches at most %s devices at once.",
				thousands(MaxBulk)))
		}
		errs := make([]error, len(targets))
		forEach(len(targets), func(i int) {
			tg := targets[i]
			errs[i] = s.checkAnyRestart(s.as(ctx, c, RoleReadOnly, *tg.device.easyPatchOrg), cl, *tg.device.endpointID, &plan.Devices[tg.check])
		})
		if err := errors.Join(errs...); err != nil {
			return RestartPlan{}, nil, err
		}
		return plan, targets, nil
	}
	byOrg := map[uuid.UUID][]int{} // EasyPatch organization → indexes into targets
	for i, tg := range targets {
		byOrg[*tg.device.easyPatchOrg] = append(byOrg[*tg.device.easyPatchOrg], i)
	}
	for org, idx := range byOrg {
		rctx := s.as(ctx, c, RoleReadOnly, org)
		pending, err := cl.RestartPending(rctx, org)
		if err != nil {
			s.noteError(err)
			return RestartPlan{}, nil, epError(err)
		}
		listed := map[uuid.UUID]PendingRestart{}
		for _, e := range pending.Endpoints {
			listed[e.ID] = e
		}
		for _, i := range idx {
			tg := targets[i]
			check := &plan.Devices[tg.check]
			e, ok := listed[*tg.device.endpointID]
			if !ok && always {
				if err := s.checkAnyRestart(rctx, cl, *tg.device.endpointID, check); err != nil {
					return RestartPlan{}, nil, err
				}
				continue
			}
			switch {
			case !ok && pending.Total > len(pending.Endpoints):
				check.Reason = "The patching engine lists only the first 1,000 restarts pending in this organization; restart it whether or not one is pending."
			case !ok:
				check.Reason = "No restart is pending."
			case !e.CanRestart:
				check.Reason = "Its EasyPatch agent cannot restart the computer; update the agent first."
			default:
				check.Restart, check.Server, check.Online = true, e.IsServer, e.IsOnline
			}
		}
	}
	return plan, targets, nil
}

// checkAnyRestart decides whether a device with no restart pending can be
// restarted anyway, and whether it is a server, from its EasyPatch endpoint.
func (s *Service) checkAnyRestart(ctx context.Context, cl *Client, endpointID uuid.UUID, check *RestartCheck) error {
	e, err := cl.Endpoint(ctx, endpointID)
	switch {
	case IsStatus(err, http.StatusNotFound):
		check.Reason = "The patching engine no longer lists its endpoint."
	case err != nil:
		s.noteError(err)
		return epError(err)
	case !slices.Contains(e.AgentCapabilities, AgentCanRestart):
		check.Reason = "Its EasyPatch agent cannot restart the computer; update the agent first."
	default:
		check.Restart, check.Online = true, e.Summary.IsOnline
		check.Server = e.OsProductType == "Server" || e.OsProductType == "DomainController"
	}
	return nil
}

// RestartInput chooses the devices of a restart, and how it restarts them.
type RestartInput struct {
	Targets
	RestartOptions
	// ConfirmServers lists the servers the person confirmed restarting.
	ConfirmServers []uuid.UUID `json:"confirmServers"`
}

// restartModeText says how a restart treats the people signed in, for the
// audit trail.
func restartModeText(o RestartOptions) string {
	switch o.Mode {
	case "Immediate":
		return "at once"
	case "PromptNoDeadline":
		return "when a signed-in user agrees"
	case "PromptWithDeadline":
		return fmt.Sprintf("when a signed-in user agrees, at the latest after %d minutes", deref(o.DeadlineMinutes, 240))
	default:
		return fmt.Sprintf("after a %d-minute countdown", deref(o.CountdownMinutes, 5))
	}
}

func deref(n *int, def int) int {
	if n == nil {
		return def
	}
	return *n
}

// Restart restarts the devices: those that have a restart pending, or all of
// them with condition Always. A server not confirmed in ConfirmServers stops
// a restart of chosen devices; a restart of every device of an organization
// or site (All) leaves it out.
func (s *Service) Restart(ctx context.Context, c access.Caller, in RestartInput) (ActionResult, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return ActionResult{}, err
	}
	if err := in.checkTargets(); err != nil {
		return ActionResult{}, err
	}
	if err := in.normalize(s.now()); err != nil {
		return ActionResult{}, err
	}
	always := in.Condition == conditionAlways
	plan, targets, err := s.planRestart(ctx, c, cl, in.Targets, always, false)
	if err != nil {
		return ActionResult{}, err
	}
	res := ActionResult{Results: []ActionItem{}, Scope: plan.Scope}
	var unconfirmed, servers []string
	left := map[uuid.UUID]bool{}
	for _, t := range targets {
		if check := plan.Devices[t.check]; check.Restart && check.Server {
			if slices.Contains(in.ConfirmServers, t.device.id) {
				servers = append(servers, t.device.name)
				continue
			}
			unconfirmed = append(unconfirmed, t.device.name)
			left[t.device.id] = true
		}
	}
	if len(unconfirmed) > 0 && !in.All {
		return ActionResult{}, apperr.Invalid("confirmServers", "These are servers; confirm restarting them: "+strings.Join(unconfirmed, ", ")+".")
	}
	var devices []deviceRow
	for _, ch := range plan.Devices {
		switch {
		case left[ch.DeviceID]:
			res.add(ActionItem{DeviceID: ch.DeviceID, DeviceName: ch.DeviceName, Message: "A server that was not ticked by name: not restarted."})
		case !ch.Restart:
			res.add(ActionItem{DeviceID: ch.DeviceID, DeviceName: ch.DeviceName, Message: ch.Reason})
		}
	}
	for _, t := range targets {
		if plan.Devices[t.check].Restart && !left[t.device.id] {
			devices = append(devices, t.device)
		}
	}
	details := map[string]any{"condition": "only if a restart is pending", "mode": restartModeText(in.RestartOptions)}
	if always {
		details["condition"] = "always"
	}
	if in.ScheduledAt != nil {
		details["scheduledAt"] = in.ScheduledAt.Format(time.RFC3339)
	}
	if in.ExpiresAfterMinutes != nil {
		details["expiresAfterMinutes"] = *in.ExpiresAfterMinutes
	}
	if len(servers) > 0 {
		details["confirmedServers"] = servers
	}
	send := func(actx context.Context, ids []uuid.UUID) (BulkResult, error) {
		return cl.BulkRestart(actx, ids, in.RestartOptions, c.Actor.Label)
	}
	if !in.All {
		actx := s.as(ctx, c, RoleAdmin, orgsOf(devices)...)
		err = s.bulk(ctx, c, devices, &res, "patch.restart", details, func(ids []uuid.UUID) (BulkResult, error) { return send(actx, ids) })
		s.fleet.clear()
		return res, err
	}
	sc := &scope{view: *plan.Scope, devices: devices}
	request := uuid.New()
	details["patchAll"], details["requestId"] = sc.view.where(), request.String()
	res.Batches, err = s.batches(ctx, c, devices, &res, "patch.restart", details, send, nil)
	s.fleet.clear()
	extra := map[string]any{"restarted": len(devices), "serversLeftOut": len(unconfirmed)}
	rctx, cancel := detached(ctx)
	defer cancel()
	err = errors.Join(err, s.recordAll(rctx, c, "patch.restart_all", sc, request, &res, details, extra))
	return res, err
}

// RetryJob runs a finished job of a device the caller may manage patching
// of again, as a new job, which it returns.
func (s *Service) RetryJob(ctx context.Context, c access.Caller, id uuid.UUID) (JobView, error) {
	old, d, _, cl, err := s.job(ctx, c, id)
	if err != nil {
		return JobView{}, err
	}
	if !c.Can(rbac.PermPatchManage, d.resource()) {
		return JobView{}, apperr.Forbidden()
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
