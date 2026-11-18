package easypatch

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// The patching engine in this deployment (one-product plan, phase B3). With
// EASYRMM_PATCHING=bundled, the connector calls the engine on loopback with
// statements (ADR-0038) instead of an EasyPatch server set up in Settings:
// the deployment configures it, so there is no token to paste and nothing
// to pair. Everything else — links, the patching pages, agent installs —
// works as with a connected server.

// engineCheckEvery is how often the engine's version and capabilities are
// read again.
const engineCheckEvery = 5 * time.Minute

// engineProbeTimeout bounds one look at the engine.
const engineProbeTimeout = 5 * time.Second

var errBundled = apperr.Conflict("patching_bundled",
	"Patching comes from the engine in this deployment (EASYRMM_PATCHING=bundled); there is no EasyPatch server to set up here.")

// engine is the patching engine and what EasyRMM last saw of it.
type engine struct {
	client *Client

	mu          sync.Mutex
	info        ServerInfo
	checkedAt   *time.Time
	lastError   string
	lastErrorAt *time.Time
}

// UseEngine makes the connector use the patching engine in this deployment
// through c (NewEngineClient). An EasyPatch server set up in Settings
// before is forgotten, with its links, which name that server's ids: as
// when Settings switches to another server. Call it before use.
func (s *Service) UseEngine(ctx context.Context, c *Client) error {
	if c == nil || !c.Engine() {
		return apperr.Invalid("engine", "not an engine client")
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		stored, err := loadConn(ctx, tx, true)
		if err != nil || stored == nil {
			return err
		}
		for _, q := range []string{`DELETE FROM easypatch_connection`, `DELETE FROM easypatch_devices`, `DELETE FROM easypatch_installs`,
			`DELETE FROM easypatch_organizations`, `DELETE FROM easypatch_sites`, `DELETE FROM easypatch_removals`, `DELETE FROM easypatch_forgotten`} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		s.log.Warn("easypatch: the patching engine in this deployment replaces the EasyPatch server set up in Settings; its links are forgotten",
			"url", stored.url)
		return s.audit.Write(ctx, tx, audit.Event{Actor: audit.SystemActor("easypatch"), Action: "easypatch.connection_delete",
			TargetType: "easypatch", TargetID: "connection", Outcome: audit.Success,
			Details: map[string]any{"url": stored.url, "reason": "replaced by the patching engine in this deployment (EASYRMM_PATCHING=bundled)"}})
	})
	if err != nil {
		return err
	}
	s.engine = &engine{client: c}
	s.fleet.clear()
	return nil
}

// Bundled reports whether patching comes from the engine in this
// deployment.
func (s *Service) Bundled() bool { return s.engine != nil }

// row is the engine as a stored connection would describe it. It reads the
// engine's version and capabilities when they are older than
// engineCheckEvery, or when force is set.
func (e *engine) row(ctx context.Context, now time.Time, force bool) *connRow {
	e.mu.Lock()
	defer e.mu.Unlock()
	if force || e.checkedAt == nil || now.Sub(*e.checkedAt) >= engineCheckEvery {
		// server-info answers anyone; the second call shows whether the
		// engine accepts EasyRMM's statements (the gateway key).
		pctx, cancel := context.WithTimeout(ctx, engineProbeTimeout)
		info, err := e.client.ServerInfo(pctx)
		can := false
		if err == nil && info.Version != "" {
			can, err = e.client.CanOperate(pctx)
		}
		cancel()
		switch {
		case err == nil && info.Version == "":
			e.lastError, e.lastErrorAt = "The patching engine does not answer like EasyPatch (no version in /api/v1/server-info).", &now
		case err == nil && !can:
			e.lastError, e.lastErrorAt = "The patching engine does not let EasyRMM act as an administrator.", &now
		case err == nil:
			if info.Capabilities == nil {
				info.Capabilities = []string{}
			}
			e.info, e.checkedAt, e.lastError, e.lastErrorAt = info, &now, "", nil
		default:
			e.lastError, e.lastErrorAt = cut(err.Error(), 1000), &now
		}
	}
	return &connRow{url: e.client.base.String(), version: e.info.Version, publicURL: e.info.PublicURL,
		capabilities: append([]string{}, e.info.Capabilities...), canOperate: true, checkedAt: e.checkedAt,
		lastError: e.lastError, lastErrorAt: e.lastErrorAt}
}

// noted records that a call to the engine failed.
func (e *engine) noted(msg string, at time.Time) {
	e.mu.Lock()
	e.lastError, e.lastErrorAt = cut(msg, 1000), &at
	e.mu.Unlock()
}

// as returns ctx carrying the statement for a call c makes to the engine:
// c as the actor, with role, in the given EasyPatch organizations only (none
// when there are none). EasyRMM has checked c's permissions already; the
// statement lets the engine check the same, a second time. Calls to a
// connected server ignore it and use EasyRMM's API token.
func (s *Service) as(ctx context.Context, c access.Caller, role string, orgs ...uuid.UUID) context.Context {
	st := Statement{Subject: ServiceSubject, Name: c.Actor.Label, Role: role, Organizations: dedupe(orgs)}
	if c.Actor.Type == audit.ActorUser && c.Actor.ID != uuid.Nil {
		st.Subject = c.Actor.ID.String()
	}
	if st.Name == "" {
		st.Name = "EasyRMM"
	}
	return WithStatement(ctx, st)
}

func dedupe(ids []uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	seen := map[uuid.UUID]bool{}
	for _, id := range ids {
		if id != uuid.Nil && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
