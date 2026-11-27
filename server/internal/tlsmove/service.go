// Package tlsmove is slice 5b2 of ADR-0055: it records, per DNS name, which
// source the name's certificate is served from (what .env gives it, Let's
// Encrypt, or the internal authority) and moves a name between them. A move
// obtains the target certificate and holds it, asks every device that uses the
// name to verify the target chain (internal/tlstrust), waits until all have,
// and then swaps the source atomically. Nothing is served from the target
// until the swap, and a cancelled move changes nothing.
package tlsmove

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
)

// The sources a name can be served from.
const (
	SourceEnv       = "env"
	SourceACME      = "acme"
	SourceAuthority = "authority"
)

// SeenWithin is how recently a device must have been seen to block a move
// (ADR-0055): a device not seen for this long is listed and does not block.
const SeenWithin = 30 * 24 * time.Hour

// Errors a caller can tell apart.
var (
	ErrBadSource   = errors.New("tlsmove: unknown source")
	ErrSameSource  = errors.New("tlsmove: the name is served from that source already")
	ErrMoveActive  = errors.New("tlsmove: a move of this name is already waiting")
	ErrNoMove      = errors.New("tlsmove: no move of this name is waiting")
	ErrUnavailable = errors.New("tlsmove: this server cannot serve that source for the name")
	ErrBadName     = errors.New("tlsmove: not a valid name")
	ErrNoChain     = errors.New("tlsmove: the target source gave no chain to verify")
)

// Prepared is what a source gives a move: the chain to serve, authorities to
// add to the agents' trust, and notes for the page.
type Prepared struct {
	Chain    [][]byte
	AddCerts [][]byte
	Notes    []string
	// AccountURL is the ACME account the order used, to record.
	AccountURL string
}

// Certs is the certificate service as a move needs it. Prepare obtains (or
// reads) the target source's certificate for a name and holds it, without
// serving it; Swap makes the edge serve the name from it, atomically, with no
// restart; SwapDelay says how long a swap must still wait (MeshCentral's name
// waits for its next read of certUrl).
type Certs interface {
	Prepare(ctx context.Context, name, target string) (Prepared, error)
	Swap(ctx context.Context, name, target string) error
	SwapDelay(ctx context.Context, name string) time.Duration
}

// Asker is the agent trust service's side of a move.
type Asker interface {
	Ask(ctx context.Context, devices []uuid.UUID, t tlstrust.Target, force bool) error
}

// Deps are what the service uses.
type Deps struct {
	DB    *database.DB
	Audit *audit.Logger
	Certs Certs
	Trust Asker
	// EasyPatchHost names the host a device's EasyPatch agent uses ("" when
	// it has none).
	EasyPatchHost func(ctx context.Context, device uuid.UUID) string
	Log           *slog.Logger
	Now           func() time.Time
}

// Service holds names' sources and runs moves.
type Service struct {
	deps Deps
	mu   sync.Mutex // one move step at a time

	// served caches each name's source for the edge, which asks at every
	// handshake. A swap replaces the entry under the lock: handshakes before
	// it get the old certificate, after it the new one, and connections
	// already open are not touched.
	smu    sync.RWMutex
	served map[string]string
}

// New builds the service.
func New(d Deps) *Service {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	return &Service{deps: d, served: map[string]string{}}
}

// Load reads every name's source into the edge's cache; call it before the
// edge serves.
func (s *Service) Load(ctx context.Context) error {
	names, err := s.Names(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]string, len(names))
	for _, n := range names {
		m[n.Name] = n.Source
	}
	s.smu.Lock()
	s.served = m
	s.smu.Unlock()
	return nil
}

// Served returns the source a name is served from, without touching the
// database: SourceEnv for any name the console never moved.
func (s *Service) Served(name string) string {
	s.smu.RLock()
	defer s.smu.RUnlock()
	if v, ok := s.served[strings.ToLower(name)]; ok {
		return v
	}
	return SourceEnv
}

func valid(s string) bool { return s == SourceEnv || s == SourceACME || s == SourceAuthority }

func normName(n string) (string, error) {
	n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
	if n == "" || len(n) > 253 || strings.ContainsAny(n, " /\\:@") {
		return "", ErrBadName
	}
	return n, nil
}

// Name is a name's source and its waiting move, as the page shows it.
type Name struct {
	Name      string     `json:"name"`
	Source    string     `json:"source"`
	Target    string     `json:"moveTarget,omitempty"`
	StartedAt *time.Time `json:"moveStartedAt,omitempty"`
	Notes     []string   `json:"moveNotes"`
}

// Source returns the source a name is served from: "env" unless the console
// chose another.
func (s *Service) Source(ctx context.Context, name string) (string, error) {
	n, err := normName(name)
	if err != nil {
		return "", err
	}
	src, _, err := s.state(ctx, n)
	return src, err
}

// Names lists every name with a recorded source or move.
func (s *Service) Names(ctx context.Context) ([]Name, error) {
	out := []Name{}
	err := s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT name, source, coalesce(move_target, ''), move_started_at, move_notes FROM tls_names ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n Name
			var notes []byte
			if err := rows.Scan(&n.Name, &n.Source, &n.Target, &n.StartedAt, &notes); err != nil {
				return err
			}
			n.Notes = []string{}
			_ = json.Unmarshal(notes, &n.Notes)
			out = append(out, n)
		}
		return rows.Err()
	})
	return out, err
}

func b64(chain [][]byte) []string {
	out := make([]string, len(chain))
	for i, c := range chain {
		out[i] = base64.StdEncoding.EncodeToString(c)
	}
	return out
}

func (s *Service) record(ctx context.Context, actor audit.Actor, name, state string, d map[string]any) {
	if s.deps.Audit == nil {
		return
	}
	d["name"], d["state"] = name, state
	if err := s.deps.Audit.Record(ctx, audit.Event{Actor: actor, Action: "tls.source_change", TargetType: "tls_name", TargetID: name,
		Outcome: audit.Success, Details: d}); err != nil {
		s.deps.Log.Error("tls: audit failed", "action", "tls.source_change", "error", err)
	}
}

// Start begins a move of name to target. The caller has already required
// step-up authentication. The target's certificate is obtained and held, and
// every device using the name is asked to verify it; the swap happens in Tick
// once all have. It returns at once with the move waiting.
func (s *Service) Start(ctx context.Context, actor audit.Actor, name, target string) error {
	n, err := normName(name)
	if err != nil {
		return err
	}
	if !valid(target) {
		return ErrBadSource
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, moving, err := s.state(ctx, n)
	if err != nil {
		return err
	}
	if moving != "" {
		return ErrMoveActive
	}
	if cur == target {
		return ErrSameSource
	}
	if s.deps.Certs == nil {
		return ErrUnavailable
	}
	cands, err := s.candidates(ctx, n)
	if err != nil {
		return err
	}
	prep, err := s.deps.Certs.Prepare(ctx, n, target)
	if err != nil {
		return err
	}
	if len(prep.Chain) == 0 {
		return ErrNoChain
	}
	if prep.Notes == nil {
		prep.Notes = []string{}
	}
	var by any
	if actor.ID != uuid.Nil {
		by = actor.ID
	}
	err = s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO tls_names (name, source, move_target, move_started_at, move_started_by, move_chain, move_add_certs, move_notes, acme_account_url)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''))
			ON CONFLICT (name) DO UPDATE SET move_target = EXCLUDED.move_target, move_started_at = EXCLUDED.move_started_at,
				move_started_by = EXCLUDED.move_started_by, move_chain = EXCLUDED.move_chain, move_add_certs = EXCLUDED.move_add_certs,
				move_notes = EXCLUDED.move_notes, acme_account_url = coalesce(EXCLUDED.acme_account_url, tls_names.acme_account_url), updated_at = now()
			WHERE tls_names.move_target IS NULL`,
			n, cur, target, s.deps.Now(), by, b64(prep.Chain), b64(prep.AddCerts), prep.Notes, prep.AccountURL)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrMoveActive
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := s.ask(ctx, n, cands, prep); err != nil {
		_ = s.clear(ctx, n)
		return err
	}
	s.record(ctx, actor, n, "requested", map[string]any{"from": cur, "to": target, "devices": len(cands)})
	return nil
}

// state returns the name's source and its waiting move's target.
func (s *Service) state(ctx context.Context, n string) (src, moving string, err error) {
	src = SourceEnv
	err = s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var mt *string
		e := tx.QueryRow(ctx, `SELECT source, move_target FROM tls_names WHERE name = $1`, n).Scan(&src, &mt)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if mt != nil {
			moving = *mt
		}
		return e
	})
	return
}

// device is one that uses a name.
type device struct {
	ID       uuid.UUID
	Org      uuid.UUID
	Hostname string
	Seen     *time.Time
	Agent    bool // its EasyRMM agent's origin is the name
	Patch    bool // its EasyPatch agent's host is the name
}

// candidates finds the devices that use the name: those whose EasyRMM agent's
// origin is the name, or has reported none (too old to say, or outside the
// development scope: it might use it, and the swap must not cut it off), and those whose EasyPatch agent's host is the name.
func (s *Service) candidates(ctx context.Context, n string) ([]device, error) {
	var all []device
	err := s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id, d.organization_id, d.hostname, d.agent_last_seen_at, coalesce(t.origin, '') IN ($1, '')
			FROM devices d LEFT JOIN device_tls_state t ON t.device_id = d.id
			WHERE d.agent_public_key IS NOT NULL ORDER BY d.hostname, d.id`, n)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d device
			if err := rows.Scan(&d.ID, &d.Org, &d.Hostname, &d.Seen, &d.Agent); err != nil {
				return err
			}
			all = append(all, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	var out []device
	for _, d := range all {
		d.Patch = s.deps.EasyPatchHost != nil && strings.EqualFold(s.deps.EasyPatchHost(ctx, d.ID), n)
		if d.Agent || d.Patch {
			out = append(out, d)
		}
	}
	return out, nil
}

func (s *Service) fresh(d device) bool {
	return d.Seen != nil && s.deps.Now().Sub(*d.Seen) <= SeenWithin
}

// ask has every device seen in the last 30 days, and inside the development
// scope (ADR-0069), verify the target chain. Devices outside the scope are
// never asked (the agent trust service sends them nothing); they block the
// move instead, so that the swap cannot cut them off.
func (s *Service) ask(ctx context.Context, n string, cands []device, p Prepared) error {
	var ids []uuid.UUID
	var patch bool
	for _, d := range cands {
		if s.fresh(d) && devscope.Allowed(d.Org) {
			ids = append(ids, d.ID)
			patch = patch || d.Patch
		}
	}
	if len(ids) == 0 {
		return nil
	}
	t := tlstrust.Target{Origin: n, Chains: []tlstrust.Chain{{Purpose: agentproto.TrustTarget, DER: p.Chain}}, AddCerts: p.AddCerts}
	if patch {
		t.EasyPatchHost, t.EasyPatchChains = n, t.Chains
	}
	return s.deps.Trust.Ask(ctx, ids, t, true)
}

func (s *Service) clear(ctx context.Context, n string) error {
	return s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE tls_names SET move_target = NULL, move_started_at = NULL, move_started_by = NULL,
			move_chain = '[]', move_add_certs = '[]', move_notes = '[]', updated_at = now() WHERE name = $1`, n); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM device_tls_trust WHERE purpose = 'target' AND host = $1`, n)
		return err
	})
}

// Cancel ends a waiting move. The name keeps its source and serves what it
// served; the verifications asked for are dropped.
func (s *Service) Cancel(ctx context.Context, actor audit.Actor, name string) error {
	n, err := normName(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, moving, err := s.state(ctx, n)
	if err != nil {
		return err
	}
	if moving == "" {
		return ErrNoMove
	}
	if err := s.clear(ctx, n); err != nil {
		return err
	}
	s.record(ctx, actor, n, "cancelled", map[string]any{"from": cur, "to": moving})
	return nil
}

// DeviceProgress is one device's verification of a move's target chain.
type DeviceProgress struct {
	DeviceID uuid.UUID  `json:"deviceId"`
	Hostname string     `json:"hostname"`
	LastSeen *time.Time `json:"lastSeen,omitempty"`
	// State is "passed", "failed", "pending" (not reported), "stale" (not seen
	// in 30 days: listed, does not block) or "outside_scope" (blocks).
	State string `json:"state"`
	Error string `json:"error,omitempty"`
	// Scopes names who must verify: "agent" and, when it has one, "easypatch".
	Scopes []string `json:"scopes"`
}

// Progress is a move's page.
type Progress struct {
	Name      string           `json:"name"`
	Source    string           `json:"source"`
	Target    string           `json:"target"`
	StartedAt time.Time        `json:"startedAt"`
	Notes     []string         `json:"notes"`
	Devices   []DeviceProgress `json:"devices"`
	// Waiting counts the devices that block the swap.
	Waiting int `json:"waiting"`
	// SwapDelaySeconds is how long the swap must still wait for MeshCentral's
	// read of certUrl.
	SwapDelaySeconds int `json:"swapDelaySeconds"`
}

type result struct{ scope, state, err string }

// Progress returns the waiting move of a name.
func (s *Service) Progress(ctx context.Context, name string) (*Progress, error) {
	n, err := normName(name)
	if err != nil {
		return nil, err
	}
	p := &Progress{Name: n, Notes: []string{}, Devices: []DeviceProgress{}}
	err = s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var notes []byte
		var tgt *string
		var started *time.Time
		e := tx.QueryRow(ctx, `SELECT source, move_target, move_started_at, move_notes FROM tls_names WHERE name = $1`, n).
			Scan(&p.Source, &tgt, &started, &notes)
		if errors.Is(e, pgx.ErrNoRows) || (e == nil && tgt == nil) {
			return ErrNoMove
		}
		if e != nil {
			return e
		}
		p.Target, p.StartedAt = *tgt, *started
		_ = json.Unmarshal(notes, &p.Notes)
		return nil
	})
	if err != nil {
		return nil, err
	}
	cands, err := s.candidates(ctx, n)
	if err != nil {
		return nil, err
	}
	results := map[uuid.UUID][]result{}
	err = s.deps.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT device_id, scope, state, error FROM device_tls_trust WHERE purpose = 'target' AND host = $1`, n)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var r result
			if err := rows.Scan(&id, &r.scope, &r.state, &r.err); err != nil {
				return err
			}
			results[id] = append(results[id], r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	for _, d := range cands {
		dp := DeviceProgress{DeviceID: d.ID, Hostname: d.Hostname, LastSeen: d.Seen, Scopes: []string{}, State: "pending"}
		want := 0
		if d.Agent {
			dp.Scopes = append(dp.Scopes, agentproto.TrustScopeAgent)
			want++
		}
		if d.Patch {
			dp.Scopes = append(dp.Scopes, agentproto.TrustScopeEasyPatch)
			want++
		}
		passed := 0
		for _, r := range results[d.ID] {
			switch r.state {
			case "passed":
				if slices.Contains(dp.Scopes, r.scope) {
					passed++
				}
			case "failed":
				dp.State, dp.Error = "failed", r.err
			}
		}
		switch {
		case !s.fresh(d):
			dp.State = "stale"
		case !devscope.Allowed(d.Org):
			dp.State = "outside_scope"
		case dp.State != "failed" && passed >= want:
			dp.State = "passed"
		}
		if dp.State != "passed" && dp.State != "stale" {
			p.Waiting++
		}
		p.Devices = append(p.Devices, dp)
	}
	if s.deps.Certs != nil {
		p.SwapDelaySeconds = int(s.deps.Certs.SwapDelay(ctx, n).Seconds())
	}
	return p, nil
}

// Tick completes every waiting move whose devices have all verified.
func (s *Service) Tick(ctx context.Context) {
	names, err := s.Names(ctx)
	if err != nil {
		s.deps.Log.Error("tls: listing moves failed", "error", err)
		return
	}
	for _, n := range names {
		if n.Target == "" {
			continue
		}
		if err := s.complete(ctx, n.Name); err != nil && !errors.Is(err, errNotYet) {
			s.deps.Log.Warn("tls: completing a move failed", "name", n.Name, "error", err)
		}
	}
}

var errNotYet = errors.New("not yet")

func (s *Service) complete(ctx context.Context, n string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.Progress(ctx, n)
	if errors.Is(err, ErrNoMove) {
		return nil
	}
	if err != nil {
		return err
	}
	if p.Waiting > 0 || p.SwapDelaySeconds > 0 {
		return errNotYet
	}
	if err := s.deps.Certs.Swap(ctx, n, p.Target); err != nil {
		return fmt.Errorf("swapping: %w", err)
	}
	err = s.deps.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE tls_names SET source = move_target, move_target = NULL, move_started_at = NULL, move_started_by = NULL,
			move_chain = '[]', move_add_certs = '[]', move_notes = '[]', updated_at = now()
			WHERE name = $1 AND move_target = $2`, n, p.Target)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotYet
		}
		// The target chain is now the served one: its rows are history.
		_, err = tx.Exec(ctx, `DELETE FROM device_tls_trust WHERE purpose = 'target' AND host = $1`, n)
		return err
	})
	if err != nil {
		return err
	}
	s.smu.Lock()
	s.served[n] = p.Target
	s.smu.Unlock()
	s.record(ctx, audit.SystemActor("tls"), n, "completed", map[string]any{"from": p.Source, "to": p.Target})
	return nil
}

// Run completes moves as devices verify, until ctx ends.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}
