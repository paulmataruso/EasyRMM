package activedirectory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Which controller does a domain's work (ADR-0075 section 3). A domain is
// the set of controllers whose status snapshots name the same domain SID.
// One controller is chosen per domain: the pinned one if it qualifies,
// else the PDC emulator if it qualifies, else the most recent heartbeat.

var domainSID = regexp.MustCompile(`^S-1-5-21-[0-9]+-[0-9]+-[0-9]+$`)

// OnlineIntervals is how many of the device's own heartbeat intervals (ADR-0058) may pass since its last heartbeat for
// a controller to count as online: two, which is two minutes at the default.
const OnlineIntervals = 2

// Health of a controller, from its last health_read snapshot.
const (
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
	HealthUnknown   = "unknown"
)

// Candidate is one enrolled controller of a domain.
type Candidate struct {
	DeviceID uuid.UUID `json:"deviceId"`
	SiteID   uuid.UUID `json:"siteId"`
	Name     string    `json:"name"`
	// Controller is the controller's own DNS name, as the directory knows it.
	Controller string     `json:"controller"`
	ReadOnly   bool       `json:"readOnly"`
	LastSeen   *time.Time `json:"lastSeen"`
	Online     bool       `json:"online"`
	// PDC says this controller holds the PDC emulator role.
	PDC    bool   `json:"pdc"`
	Health string `json:"health"`
	// ReadAt is when its status was read.
	ReadAt *time.Time `json:"readAt"`
}

// qualifies says whether a controller may do a write now.
func (c Candidate) qualifies() bool { return c.Online && !c.ReadOnly }

// Select picks the controller for a write, and says why. It never picks an
// offline or read-only controller. A controller known to be unhealthy is
// chosen only when no other qualifies, and one whose health is unknown only
// when no healthy one does. It returns nil when none qualifies.
func Select(cands []Candidate, pinned uuid.UUID) (*Candidate, string) {
	var pool []Candidate
	for _, rank := range []string{HealthHealthy, HealthUnknown, HealthUnhealthy} {
		pool = pool[:0]
		for _, c := range cands {
			if c.qualifies() && c.Health == rank {
				pool = append(pool, c)
			}
		}
		if len(pool) == 0 {
			continue
		}
		if pinned != uuid.Nil {
			for i := range pool {
				if pool[i].DeviceID == pinned {
					return &pool[i], "pinned"
				}
			}
		}
		for i := range pool {
			if pool[i].PDC {
				return &pool[i], "pdc"
			}
		}
		slices.SortFunc(pool, func(a, b Candidate) int {
			switch {
			case a.LastSeen != nil && b.LastSeen != nil && !a.LastSeen.Equal(*b.LastSeen):
				return b.LastSeen.Compare(*a.LastSeen)
			default:
				return strings.Compare(a.DeviceID.String(), b.DeviceID.String())
			}
		})
		why := "heartbeat"
		if rank != HealthHealthy {
			why += "_" + rank
		}
		return &pool[0], why
	}
	return nil, "none_qualifies"
}

// Domain is one domain of an organization, as the card shows it.
type Domain struct {
	SID         string      `json:"sid"`
	Name        string      `json:"name"`
	Controllers []Candidate `json:"controllers"`
	Pinned      *uuid.UUID  `json:"pinned"`
	Chosen      *uuid.UUID  `json:"chosen"`
	// Why is how the chosen one was picked, or why none was.
	Why string `json:"why"`
	// LockedOut and ReplicationFailures are from the chosen controller's last health read; null where unknown.
	LockedOut           *int `json:"lockedOut"`
	ReplicationFailures *int `json:"replicationFailures"`
	// Worst is the worst check state of the chosen controller's health read.
	Worst string `json:"worst"`
}

// Domains is the card.
type Domains struct {
	Enabled bool     `json:"enabled"`
	Domains []Domain `json:"domains"`
}

// Service reads the domains of an organization and pins their controllers.
type Service struct {
	db    *database.DB
	mods  *modules.Service
	audit *audit.Logger
	now   func() time.Time
}

// New builds the service.
func New(db *database.DB, mods *modules.Service, a *audit.Logger) *Service {
	return &Service{db: db, mods: mods, audit: a, now: time.Now}
}

func worst(checks []Check) string {
	rank := map[string]int{"ok": 0, "not_applicable": 0, "unknown": 1, "could_not_run": 1, "warning": 2, "critical": 3}
	w, best := "ok", 0
	for _, c := range checks {
		if r := rank[c.State]; r > best {
			w, best = c.State, r
		}
	}
	return w
}

// Read returns the domains an organization's enrolled controllers belong to.
// It needs ad.view; a controller counts only where the module is on and the
// caller may view it at the controller's site. It reads stored snapshots and
// sends no job.
func (s *Service) Read(ctx context.Context, c access.Caller, org uuid.UUID) (*Domains, error) {
	if !c.CanInOrg(rbac.PermADView, org) {
		return nil, apperr.NotFound()
	}
	out := &Domains{Domains: []Domain{}}
	type row struct {
		id, site       uuid.UUID
		name           string
		seen           *time.Time
		interval       int
		status, health []byte
		statusAt       *time.Time
	}
	var rows []row
	pins := map[string]uuid.UUID{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `
			SELECT d.id, d.site_id, d.name, d.agent_last_seen_at, d.agent_heartbeat_seconds, st.data, st.taken_at, h.data
			FROM devices d
			LEFT JOIN windows_module_snapshots st ON st.device_id = d.id AND st.action = 'active_directory.status' AND st.params_hash = ''
			LEFT JOIN windows_module_snapshots h  ON h.device_id = d.id AND h.action = 'active_directory.health_read' AND h.params_hash = ''
			WHERE d.organization_id = $1 AND d.platform = 'windows' AND d.roles @> '[{"name":"ad_ds"}]'
			ORDER BY d.name, d.id`, org)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var x row
			if err := r.Scan(&x.id, &x.site, &x.name, &x.seen, &x.interval, &x.status, &x.statusAt, &x.health); err != nil {
				return err
			}
			rows = append(rows, x)
		}
		if err := r.Err(); err != nil {
			return err
		}
		p, err := tx.Query(ctx, `SELECT domain_sid, preferred_device_id FROM ad_domains WHERE organization_id = $1 AND preferred_device_id IS NOT NULL`, org)
		if err != nil {
			return err
		}
		defer p.Close()
		for p.Next() {
			var sid string
			var dev uuid.UUID
			if err := p.Scan(&sid, &dev); err != nil {
				return err
			}
			pins[sid] = dev
		}
		return p.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("activedirectory: reading the domains: %w", err)
	}
	now := s.now()
	healths := map[uuid.UUID]*Health{}
	byDomain := map[string]*Domain{}
	var order []string
	for _, x := range rows {
		if !c.Can(rbac.PermADView, rbac.Site(org, x.site)) || !s.mods.Allowed(ctx, org, x.site, modules.ActiveDirectory) {
			continue
		}
		out.Enabled = true
		var st Status
		if len(x.status) == 0 || json.Unmarshal(x.status, &st) != nil || st.DomainSID == "" {
			continue // not read yet: it has no domain to belong to
		}
		cand := Candidate{DeviceID: x.id, SiteID: x.site, Name: x.name, Controller: st.Controller, ReadOnly: st.ReadOnly, LastSeen: x.seen,
			PDC: strings.EqualFold(st.Controller, st.PDCEmulator), Health: HealthUnknown, ReadAt: x.statusAt}
		cand.Online = x.seen != nil && now.Sub(*x.seen) <= OnlineIntervals*time.Duration(x.interval)*time.Second
		if len(x.health) > 0 {
			var h Health
			if json.Unmarshal(x.health, &h) == nil {
				healths[x.id] = &h
				switch w := worst(h.Checks); w {
				case "critical":
					cand.Health = HealthUnhealthy
				case "ok", "warning", "not_applicable":
					cand.Health = HealthHealthy
				}
			}
		}
		d := byDomain[st.DomainSID]
		if d == nil {
			d = &Domain{SID: st.DomainSID, Name: st.Domain, Controllers: []Candidate{}}
			byDomain[st.DomainSID] = d
			order = append(order, st.DomainSID)
		}
		d.Controllers = append(d.Controllers, cand)
	}
	for _, sid := range order {
		d := byDomain[sid]
		pin := pins[sid]
		if pin != uuid.Nil {
			d.Pinned = &pin
		}
		ch, why := Select(d.Controllers, pin)
		d.Why = why
		if ch != nil {
			id := ch.DeviceID
			d.Chosen = &id
			if h := healths[id]; h != nil {
				d.LockedOut, d.Worst = h.LockedOutCount, worst(h.Checks)
				n := h.Replication.FailureCount
				d.ReplicationFailures = &n
			}
		}
		out.Domains = append(out.Domains, *d)
	}
	return out, nil
}

// Pin sets, or with a nil device clears, the controller an organization
// prefers for a domain. It needs ad.manage on the organization; the device
// must be an enrolled controller of the organization. The pin is a
// preference: a controller that does not qualify is not chosen.
func (s *Service) Pin(ctx context.Context, c access.Caller, org uuid.UUID, sid string, device *uuid.UUID) error {
	if !c.Can(rbac.PermADManage, rbac.Org(org)) {
		return apperr.NotFound()
	}
	if !domainSID.MatchString(sid) {
		return apperr.Invalid("sid", "This is not a domain's security identifier.")
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if device != nil {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE id = $1 AND organization_id = $2 AND roles @> '[{"name":"ad_ds"}]')`, *device, org).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return apperr.Invalid("deviceId", "That computer is not a domain controller of this organization.")
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ad_domains (organization_id, domain_sid, preferred_device_id) VALUES ($1, $2, $3)
			ON CONFLICT (organization_id, domain_sid) DO UPDATE SET preferred_device_id = excluded.preferred_device_id, updated_at = now()`, org, sid, device); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "active_directory.pin", Outcome: audit.Success, OrganizationID: org, TargetType: "ad_domain", TargetID: sid,
			Details: map[string]any{"device": device},
		})
	})
	var ae *apperr.Error
	if errors.As(err, &ae) {
		return err
	}
	if err != nil {
		return fmt.Errorf("activedirectory: pinning: %w", err)
	}
	return nil
}
