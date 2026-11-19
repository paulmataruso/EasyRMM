package easypatch

import (
	"context"
	"net/mail"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// The patching engine in this deployment (one-product plan, phases B3 and
// S). The connector calls the engine on loopback with statements (ADR-0038)
// instead of an EasyPatch server set up in Settings:
// the deployment configures it, so there is no token to paste and nothing
// to pair. Everything else — links, the patching pages, agent installs —
// works as with a connected server.

// engineCheckEvery is how often the engine's version and capabilities are
// read again.
const engineCheckEvery = 5 * time.Minute

// engineProbeTimeout bounds one look at the engine.
const engineProbeTimeout = 5 * time.Second

var errBundled = apperr.Conflict("patching_bundled",
	"Patching comes from the engine in this deployment; there is no EasyPatch server to set up here.")

// engine is the patching engine and what EasyRMM last saw of it.
type engine struct {
	client *Client
	// agentCA, when set, gives the certificate authority of the engine's
	// public address, for EasyPatch agents to trust (one-product plan, B7).
	agentCA func() []byte
	// mail is EasyRMM's mail server, which the engine sends reports with;
	// mailSynced says the engine has it (one-product plan, C5).
	mail       *MailConfig
	mailSynced bool
	// importedURLs are an imported EasyPatch's addresses, which its agents
	// still use (AgentHostnames).
	importedURLs []string

	mu          sync.Mutex
	info        ServerInfo
	checkedAt   *time.Time
	lastError   string
	lastErrorAt *time.Time
}

// EngineOption configures UseEngine.
type EngineOption func(*engine)

// AgentCA has EasyPatch agents installed through EasyRMM trust ca (PEM)
// for the engine's public address, which is EasyRMM's: its own authority
// when EasyRMM is addressed by IP (EASYRMM_TLS_MODE=internal). The Windows
// agent gets it as the MSI's SERVERCACERT, the Linux agent with enroll's
// --server-ca, each for that one server only.
func AgentCA(ca func() []byte) EngineOption {
	return func(e *engine) { e.agentCA = ca }
}

// AgentHostnames are an imported, standalone EasyPatch's names
// (EASYRMM_PATCHING_AGENT_HOSTNAMES), which its agents enrolled with and
// still use: EasyRMM's edge serves them, and an agent reporting one of them
// is the engine's (one-product plan, phase S).
func AgentHostnames(names []string) EngineOption {
	return func(e *engine) {
		for _, n := range names {
			e.importedURLs = append(e.importedURLs, "https://"+n)
		}
	}
}

// MailConfig is EasyRMM's mail server (EASYRMM_SMTP_*). An empty Host means
// EasyRMM has none.
type MailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// TLS is starttls, implicit or none.
	TLS string
}

// Mail has the engine email monthly reports through EasyRMM's mail server:
// the reconciler gives the engine cfg, and removes the engine's when cfg has
// no host, so the deployment has one mail server.
func Mail(cfg MailConfig) EngineOption {
	return func(e *engine) { e.mail = &cfg }
}

// mailSettings is cfg as the engine's mail settings, keeping what EasyRMM
// does not set from the engine's current ones.
func (cfg MailConfig) mailSettings(current MailSettings) MailSettingsInput {
	security := map[string]string{"starttls": "StartTls", "implicit": "SslOnConnect", "none": "None"}[cfg.TLS]
	if security == "" {
		security = "StartTls"
	}
	password := cfg.Password
	from, name := cfg.From, "EasyRMM"
	if a, err := mail.ParseAddress(cfg.From); err == nil {
		from = a.Address
		if a.Name != "" {
			name = a.Name
		}
	}
	in := MailSettingsInput{SMTPHost: cfg.Host, SMTPPort: cfg.Port, SMTPSecurity: security, SMTPUsername: cfg.Username, SMTPPassword: &password,
		FromAddress: from, FromName: name, AllowPrivateNetworkWebhooks: current.AllowPrivateNetworkWebhooks}
	if cfg.Host == "" {
		in.SMTPPort, in.SMTPSecurity, in.SMTPUsername, in.FromAddress = 587, "StartTls", "", ""
	}
	if in.SMTPPort == 0 {
		in.SMTPPort = 587
	}
	return in
}

// syncMail gives the engine EasyRMM's mail server, once per start: the
// engine may not be up when EasyRMM starts, so each pass tries until it is
// done.
func (s *Service) syncMail(ctx context.Context, c *Client, res *ReconcileResult) {
	e := s.engine
	if e == nil || e.mail == nil {
		return
	}
	e.mu.Lock()
	done := e.mailSynced
	e.mu.Unlock()
	if done {
		return
	}
	st := WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "EasyRMM", Role: RoleSuperAdmin, AllOrganizations: true})
	current, err := c.MailSettings(st)
	if err == nil {
		err = c.SetMailSettings(st, e.mail.mailSettings(current))
	}
	if err != nil {
		res.problem("could not give the patching engine EasyRMM's mail server: %v", err)
		return
	}
	e.mu.Lock()
	e.mailSynced = true
	e.mu.Unlock()
	s.log.Info("patching: the engine sends reports through EasyRMM's mail server", "host", e.mail.Host)
}

// UseEngine makes the connector use the patching engine in this deployment
// through c (NewEngineClient). An EasyPatch server set up in Settings
// before is forgotten, with its links, which name that server's ids: as
// when Settings switches to another server. Call it before use.
func (s *Service) UseEngine(ctx context.Context, c *Client, opts ...EngineOption) error {
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
			Details: map[string]any{"url": stored.url, "reason": "replaced by the patching engine in this deployment"}})
	})
	if err != nil {
		return err
	}
	e := &engine{client: c}
	for _, o := range opts {
		o(e)
	}
	s.engine = e
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
	var ca string
	if e.agentCA != nil {
		ca = string(e.agentCA())
	}
	return &connRow{url: e.client.base.String(), caCert: ca, version: e.info.Version, publicURL: e.info.PublicURL,
		importedURLs: e.importedURLs, capabilities: append([]string{}, e.info.Capabilities...), canOperate: true, checkedAt: e.checkedAt,
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
	st := s.statement(c, role)
	st.Organizations = dedupe(orgs)
	return WithStatement(ctx, st)
}

// statement names the caller and the role a call needs, in no organization.
func (s *Service) statement(c access.Caller, role string) Statement {
	st := Statement{Subject: ServiceSubject, Name: c.Actor.Label, Role: role}
	if c.Actor.Type == audit.ActorUser && c.Actor.ID != uuid.Nil {
		st.Subject = c.Actor.ID.String()
	}
	if st.Name == "" {
		st.Name = "EasyRMM"
	}
	return st
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
