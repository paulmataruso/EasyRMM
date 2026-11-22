package easypatch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
)

// Every available update (ADR-0030, amended 2026-11-22): Update all now
// installs, on each device, every update the engine reports missing or
// failed there, rather than those its policy installs on its own, but never
// one excluded on the device or held, nor an application update the policy
// does not approve, and feature upgrades only when asked for. Each device's
// updates are read from the engine and installed as chosen updates.

// excludedListed is how many devices with excluded updates are named.
const excludedListed = 50

// AvailableInput chooses the devices whose available updates are counted.
type AvailableInput struct {
	Targets
	// Features counts feature upgrades in; SkipDelayed leaves out those
	// still in the policy's rollout delay.
	Features    bool `json:"features"`
	SkipDelayed bool `json:"skipDelayed"`
}

// CategoryCount is how many updates of an engine category would install.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// DeviceCount is a count on one device.
type DeviceCount struct {
	DeviceID   uuid.UUID `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	Count      int       `json:"count"`
}

// DeviceError says why a device's updates could not be read.
type DeviceError struct {
	DeviceID   uuid.UUID `json:"deviceId"`
	DeviceName string    `json:"deviceName"`
	Message    string    `json:"message"`
}

// ExcludedCount counts the updates left out because they are excluded, and
// names the first devices that have them.
type ExcludedCount struct {
	Count   int           `json:"count"`
	Devices []DeviceCount `json:"devices"`
}

// AvailablePlan is what installing every available update would install.
type AvailablePlan struct {
	// Devices have at least one update to install, Updates in all; UpToDate
	// devices have none.
	Devices    int             `json:"devices"`
	Updates    int             `json:"updates"`
	UpToDate   int             `json:"upToDate"`
	Categories []CategoryCount `json:"categories"`
	// Features counts the feature upgrades found: they install only when
	// asked for.
	Features int `json:"features"`
	// Excluded, Held and NotApproved count the updates left out; Deferred,
	// those the policy's rollout delay holds back, included unless asked
	// not to be.
	Excluded    ExcludedCount `json:"excluded"`
	Held        int           `json:"held"`
	NotApproved int           `json:"notApproved"`
	Deferred    int           `json:"deferred"`
	Errors      []DeviceError `json:"errors"`
	Scope       *ScopeView    `json:"scope,omitempty"`
}

// available is one device's available updates.
type available struct {
	device  deviceRow
	updates []uuid.UUID
	err     error
	// What was counted: categories of those to install, and those left out.
	categories                                     map[string]int
	features, excluded, held, notApproved, delayed int
}

// readAvailable reads each device's available updates from the engine.
func (s *Service) readAvailable(ctx context.Context, c access.Caller, cl *Client, devices []deviceRow, features, skipDelayed bool) []available {
	out := make([]available, len(devices))
	now := s.now()
	forEach(len(devices), func(i int) {
		d := devices[i]
		a := available{device: d, categories: map[string]int{}}
		list, err := cl.Updates(s.as(ctx, c, RoleReadOnly, orgOf(d)...), *d.endpointID, "")
		if err != nil {
			s.noteError(err)
			a.err = epError(err)
			out[i] = a
			return
		}
		for _, u := range list {
			// The engine marks an excluded update Excluded while it is
			// missing or failed; one installed keeps its state
			// (ComplianceService.ApplyRequirementFlags).
			installable := u.State == "Missing" || u.State == "Failed"
			delayed := u.DeferredUntil != nil && u.DeferredUntil.After(now)
			switch {
			case u.State == "Excluded" || (u.IsExcluded && installable):
				a.excluded++
			case !installable:
			case u.HoldReason != "":
				a.held++
			case u.Category == "Application" && !u.IsRequired && u.DeferredUntil == nil:
				// The policy approves an application update it requires, or
				// one it holds back for its rollout delay only
				// (UpdateRequirement.Evaluate).
				a.notApproved++
			case u.Category == "Feature" && !features:
				a.features++
			case delayed && skipDelayed:
				a.delayed++
			default:
				if u.Category == "Feature" {
					a.features++
				}
				if delayed {
					a.delayed++
				}
				a.categories[u.Category]++
				a.updates = append(a.updates, u.UpdateGUID)
			}
		}
		out[i] = a
	})
	return out
}

// PlanAvailable says what installing every available update on the devices
// would install, without installing anything.
func (s *Service) PlanAvailable(ctx context.Context, c access.Caller, in AvailableInput) (AvailablePlan, error) {
	_, cl, err := s.operable(ctx)
	if err != nil {
		return AvailablePlan{}, err
	}
	if err := in.checkTargets(); err != nil {
		return AvailablePlan{}, err
	}
	plan := AvailablePlan{Categories: []CategoryCount{}, Excluded: ExcludedCount{Devices: []DeviceCount{}}, Errors: []DeviceError{}}
	var devices []deviceRow
	if in.All {
		sc, err := s.resolveAll(ctx, c, in.Targets)
		if err != nil {
			return AvailablePlan{}, err
		}
		devices, plan.Scope = sc.devices, &sc.view
	} else {
		res := ActionResult{}
		if devices, err = s.targets(ctx, c, in.DeviceIDs, &res); err != nil {
			return AvailablePlan{}, err
		}
		for _, it := range res.Results {
			plan.Errors = append(plan.Errors, DeviceError{DeviceID: it.DeviceID, DeviceName: it.DeviceName, Message: it.Message})
		}
	}
	if len(devices) > MaxBulk {
		return AvailablePlan{}, availableLimit()
	}
	categories := map[string]int{}
	for _, a := range s.readAvailable(ctx, c, cl, devices, in.Features, in.SkipDelayed) {
		if a.err != nil {
			plan.Errors = append(plan.Errors, DeviceError{DeviceID: a.device.id, DeviceName: a.device.name, Message: message(a.err)})
			continue
		}
		if len(a.updates) == 0 {
			plan.UpToDate++
		} else {
			plan.Devices++
			plan.Updates += len(a.updates)
		}
		for k, n := range a.categories {
			categories[k] += n
		}
		plan.Features += a.features
		plan.Held += a.held
		plan.NotApproved += a.notApproved
		plan.Deferred += a.delayed
		if a.excluded > 0 {
			plan.Excluded.Count += a.excluded
			if len(plan.Excluded.Devices) < excludedListed {
				plan.Excluded.Devices = append(plan.Excluded.Devices, DeviceCount{DeviceID: a.device.id, DeviceName: a.device.name, Count: a.excluded})
			}
		}
	}
	for k, n := range categories {
		plan.Categories = append(plan.Categories, CategoryCount{Category: k, Count: n})
	}
	slices.SortFunc(plan.Categories, func(a, b CategoryCount) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return compareText(a.Category, b.Category)
	})
	return plan, nil
}

func compareText(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func availableLimit() error {
	return apperr.Invalid("updates", fmt.Sprintf("Every available update reaches at most %s devices at once: choose a site, "+
		"or the updates each device's policy allows.", thousands(MaxBulk)))
}

// installAvailable installs every available update on each device, as
// chosen updates, a few devices at a time. The engine takes at most
// MaxSelected chosen updates in one install, so a device with more installs
// them in several jobs, which it runs one after another (the engine gives
// an endpoint one install at a time, JobService.LeaseForCheckInAsync). Each
// device's installs are sent, and their restart kept, whatever becomes of
// the request; once it has ended, no further device is sent.
func (s *Service) installAvailable(ctx context.Context, c access.Caller, cl *Client, devices []deviceRow, in InstallInput, res *ActionResult,
	details map[string]any, keep *restartKeeper) error {
	found := s.readAvailable(ctx, c, cl, devices, in.Features, in.SkipDelayed)
	items := make([]ActionItem, len(found))
	events := make([][]audit.Event, len(found))
	kept := make([]error, len(found))
	forEach(len(found), func(i int) {
		a := found[i]
		d := a.device
		items[i] = ActionItem{DeviceID: d.id, DeviceName: d.name}
		switch {
		case a.err != nil:
			items[i].Message = "Its updates could not be read: " + cut(message(a.err), 400)
			return
		case len(a.updates) == 0:
			items[i].OK, items[i].UpToDate, items[i].Message = true, true, "Already up to date: it has no available update."
			return
		case ctx.Err() != nil:
			items[i].Message = "Not sent: the request ended before this device was sent."
			return
		}
		sctx, cancel := detached(ctx)
		defer cancel()
		actx := s.as(sctx, c, RoleAdmin, orgOf(d)...)
		var jobs []uuid.UUID
		var failure error
		sent := 0
		parts := (len(a.updates) + MaxSelected - 1) / MaxSelected
		for lo := 0; lo < len(a.updates); lo += MaxSelected {
			part := a.updates[lo:min(lo+MaxSelected, len(a.updates))]
			j, err := cl.Install(actx, *d.endpointID, part, in.ScheduledAt, c.Actor.Label)
			if err != nil {
				failure = err
				break
			}
			jobs, sent = append(jobs, j.ID), sent+len(part)
			det := map[string]any{"device": d.name, "endpointId": d.endpointID.String(), "jobId": j.ID.String()}
			for k, v := range details {
				det[k] = v
			}
			det["updateCount"] = len(part)
			if parts > 1 {
				det["part"] = fmt.Sprintf("%d of %d", len(jobs), parts)
			}
			events[i] = append(events[i], audit.Event{Actor: c.Actor, Action: "patch.install", OrganizationID: d.organizationID, SiteID: d.siteID,
				DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success, Details: det})
		}
		if failure != nil && !IsStatus(failure, http.StatusConflict) && !IsStatus(failure, http.StatusBadRequest) {
			s.noteError(failure)
		}
		switch {
		case len(jobs) == 0:
			items[i].Message = cut(message(epError(failure)), 500)
			return
		case failure != nil:
			items[i].Message = cut(fmt.Sprintf("Installs %s of its %s updates, in %s; the patching engine did not take the rest: %s",
				thousands(sent), thousands(len(a.updates)), plural(len(jobs), "job"), message(epError(failure))), 500)
		case len(jobs) > 1:
			items[i].Message = fmt.Sprintf("Installs its %s updates in %d jobs of at most %d, one after another.",
				thousands(len(a.updates)), len(jobs), MaxSelected)
		}
		items[i].OK, items[i].JobID = true, &jobs[len(jobs)-1]
		if len(jobs) > 1 {
			items[i].JobIDs = jobs
		}
		kept[i] = keep.keep(sctx, []deviceRow{d}, []ActionItem{items[i]})
	})
	var list []audit.Event
	for i, it := range items {
		res.add(it)
		list = append(list, events[i]...)
	}
	rctx, cancel := detached(ctx)
	defer cancel()
	return errors.Join(append(kept, s.record(rctx, list))...)
}

// plural writes a count of things: 1 job, 2 jobs.
func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return thousands(n) + " " + what + "s"
}
