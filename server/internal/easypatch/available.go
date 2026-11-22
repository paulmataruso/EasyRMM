package easypatch

import (
	"context"
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
	// Features counts feature upgrades in.
	Features bool `json:"features"`
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
	// those included although the policy's rollout delay holds them back.
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
func (s *Service) readAvailable(ctx context.Context, c access.Caller, cl *Client, devices []deviceRow, features bool) []available {
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
			switch {
			case u.IsExcluded || u.State == "Excluded":
				a.excluded++
			case u.State != "Missing" && u.State != "Failed":
			case u.HoldReason != "":
				a.held++
			case u.Category == "Application" && !u.IsRequired:
				a.notApproved++
			case u.Category == "Feature" && !features:
				a.features++
			default:
				if u.Category == "Feature" {
					a.features++
				}
				if u.DeferredUntil != nil && u.DeferredUntil.After(now) {
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
	for _, a := range s.readAvailable(ctx, c, cl, devices, in.Features) {
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
// chosen updates, a few devices at a time.
func (s *Service) installAvailable(ctx context.Context, c access.Caller, cl *Client, devices []deviceRow, in InstallInput, res *ActionResult,
	details map[string]any) error {
	found := s.readAvailable(ctx, c, cl, devices, in.Features)
	items := make([]ActionItem, len(found))
	events := make([]*audit.Event, len(found))
	forEach(len(found), func(i int) {
		a := found[i]
		d := a.device
		items[i] = ActionItem{DeviceID: d.id, DeviceName: d.name}
		switch {
		case a.err != nil:
			items[i].Message = "Its updates could not be read: " + cut(message(a.err), 400)
			return
		case len(a.updates) == 0:
			items[i].OK, items[i].Message = true, "Nothing to install: it has no available update."
			return
		}
		updates := a.updates
		if len(updates) > 1000 {
			updates = updates[:1000]
			items[i].Message = fmt.Sprintf("Installs 1,000 of its %s updates; install again for the rest.", thousands(len(a.updates)))
		}
		j, err := cl.Install(s.as(ctx, c, RoleAdmin, orgOf(d)...), *d.endpointID, updates, in.ScheduledAt, c.Actor.Label)
		if err != nil {
			if !IsStatus(err, http.StatusConflict) && !IsStatus(err, http.StatusBadRequest) {
				s.noteError(err)
			}
			items[i].Message = cut(message(epError(err)), 500)
			return
		}
		items[i].OK, items[i].JobID = true, &j.ID
		det := map[string]any{"device": d.name, "endpointId": d.endpointID.String(), "jobId": j.ID.String()}
		for k, v := range details {
			det[k] = v
		}
		det["updateCount"] = len(updates)
		events[i] = &audit.Event{Actor: c.Actor, Action: "patch.install", OrganizationID: d.organizationID, SiteID: d.siteID,
			DeviceID: d.id, TargetType: "device", TargetID: d.id.String(), Outcome: audit.Success, Details: det}
	})
	var list []audit.Event
	for i, it := range items {
		res.add(it)
		if events[i] != nil {
			list = append(list, *events[i])
		}
	}
	return s.record(ctx, list)
}
