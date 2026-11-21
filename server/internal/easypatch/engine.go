package easypatch

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
)

// The patching engine in this deployment (ADR-0046): EasyRMM calls it on
// loopback with statements (ADR-0038). The deployment configures it, so there
// is no token to paste and nothing to pair.

// engineCheckEvery is how often the engine's version is read again.
const engineCheckEvery = 5 * time.Minute

// engineProbeTimeout bounds one look at the engine.
const engineProbeTimeout = 5 * time.Second

// engine is the patching engine and what EasyRMM last saw of it.
type engine struct {
	client *Client
	// agentCA, when set, gives the certificate authority of the engine's
	// public address, for EasyPatch agents to trust (ADR-0042).
	agentCA func() []byte
	// mail reads EasyRMM's mail server in force, which the engine sends
	// its email and reports with; mailGiven is the one last given to the
	// engine, nil until one was.
	mail      func(context.Context) (MailConfig, error)
	mailGiven *MailConfig
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
// still use (ADR-0045): EasyRMM's edge serves them, and an agent reporting
// one of them is the engine's.
func AgentHostnames(names []string) EngineOption {
	return func(e *engine) {
		for _, n := range names {
			e.importedURLs = append(e.importedURLs, "https://"+n)
		}
	}
}

// MailConfig is EasyRMM's mail server in force: .env's EASYRMM_SMTP_* or
// the console's (ADR-0053). An empty Host means EasyRMM has none.
type MailConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	// FromAddress is the sender's address, FromName its name.
	FromAddress string
	FromName    string
	// Security is starttls, tls or none.
	Security string
}

// Mail has the engine email through EasyRMM's mail server, which source
// reads: each reconcile pass gives the engine the mail server in force
// when it is not the one last given, at start and after every change, and
// removes the engine's when EasyRMM has none, so the deployment has one
// mail server.
func Mail(source func(context.Context) (MailConfig, error)) EngineOption {
	return func(e *engine) { e.mail = source }
}

// mailSettings is cfg as the engine's mail settings, keeping what EasyRMM
// does not set from the engine's current ones.
func (cfg MailConfig) mailSettings(current MailSettings) MailSettingsInput {
	security := map[string]string{"starttls": "StartTls", "tls": "SslOnConnect", "none": "None"}[cfg.Security]
	if security == "" {
		security = "StartTls"
	}
	password := cfg.Password
	name := cfg.FromName
	if name == "" {
		name = "EasyRMM"
	}
	in := MailSettingsInput{SMTPHost: cfg.Host, SMTPPort: cfg.Port, SMTPSecurity: security, SMTPUsername: cfg.Username, SMTPPassword: &password,
		FromAddress: cfg.FromAddress, FromName: name, AllowPrivateNetworkWebhooks: current.AllowPrivateNetworkWebhooks}
	if cfg.Host == "" {
		in.SMTPPort, in.SMTPSecurity, in.SMTPUsername, in.FromAddress = 587, "StartTls", "", ""
	}
	if in.SMTPPort == 0 {
		in.SMTPPort = 587
	}
	return in
}

// syncMail gives the engine EasyRMM's mail server in force when it is not
// the one last given: the engine may not be up when EasyRMM starts, or
// when the mail server changes, so each pass tries until it is done.
func (s *Service) syncMail(ctx context.Context, c *Client, res *ReconcileResult) {
	e := s.engine
	if e == nil || e.mail == nil {
		return
	}
	cfg, err := e.mail(ctx)
	if err != nil {
		res.problem("could not read EasyRMM's mail server for the patching engine: %v", err)
		return
	}
	e.mu.Lock()
	given := e.mailGiven != nil && *e.mailGiven == cfg
	e.mu.Unlock()
	if given {
		return
	}
	st := WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "EasyRMM", Role: RoleSuperAdmin, AllOrganizations: true})
	current, err := c.MailSettings(st)
	if err == nil {
		err = c.SetMailSettings(st, cfg.mailSettings(current))
	}
	if err != nil {
		res.problem("could not give the patching engine EasyRMM's mail server: %v", err)
		return
	}
	e.mu.Lock()
	e.mailGiven = &cfg
	e.mu.Unlock()
	if cfg.Host == "" {
		s.log.Info("patching: the engine has no mail server, as EasyRMM has none")
		return
	}
	s.log.Info("patching: the engine sends email and reports through EasyRMM's mail server", "host", cfg.Host)
}

// UseEngine has the service use the patching engine through c
// (NewEngineClient). Call it before use.
func (s *Service) UseEngine(c *Client, opts ...EngineOption) error {
	if c == nil {
		return apperr.Invalid("engine", "no engine client")
	}
	e := &engine{client: c}
	for _, o := range opts {
		o(e)
	}
	s.engine = e
	s.fleet.clear()
	return nil
}

// row is what EasyRMM knows of the engine. It reads the engine's version
// when it is older than engineCheckEvery, or when force is set.
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
			e.lastError, e.lastErrorAt = "The patching engine does not answer as expected (no version in /api/v1/server-info).", &now
		case err == nil && !can:
			e.lastError, e.lastErrorAt = "The patching engine does not let EasyRMM act as an administrator.", &now
		case err == nil:
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
		importedURLs: e.importedURLs, checkedAt: e.checkedAt, lastError: e.lastError, lastErrorAt: e.lastErrorAt}
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
// statement lets the engine check the same, a second time.
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
