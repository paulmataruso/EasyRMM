package easypatch

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
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
	// its email and reports with; without it, this service leaves the
	// engine's mail settings alone. mailLock serializes every change of
	// the engine's mail settings on this server, so that each gives the
	// engine one mail server whole, and is taken with the caller's
	// context, so that a request does not wait past its end. Under it:
	// mailGiven is the mail server last given, nil until one was;
	// mailFailures counts the passes in a row that could not give it;
	// mailRecorded is the one last recorded as given (mail_engine_given);
	// and mailCompared is what a server that does not give it last
	// compared with that record.
	mail         func(context.Context) (MailConfig, error)
	mailKey      []byte
	mailLock     chan struct{}
	mailGiven    *MailConfig
	mailFailures int
	mailRecorded *MailConfig
	mailCompared *mailComparison
	// mailLeader chooses the one of EasyRMM's servers that gives the
	// engine its mail server; nil without a database, when this one does.
	mailLeader *database.Leader
	// mailTimeout bounds each call to the engine made holding mailLock.
	mailTimeout time.Duration
	// importedURLs are an imported EasyPatch's addresses, which its agents
	// still use (AgentHostnames).
	importedURLs []string

	mu          sync.Mutex
	info        ServerInfo
	checkedAt   *time.Time
	lastError   string
	lastErrorAt *time.Time
	// mailProblem says why the engine does not have this server's mail
	// server: it could not be given it, mailFailLimit passes in a row, or
	// with the webhook switch; or another server gave it another
	// (compareMail). "" otherwise.
	mailProblem string
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
// when it is not the one last given or the engine's differs, at start and
// after every change, and removes the engine's when EasyRMM has none, so
// the deployment has one mail server. EasyRMM is its one source: a change
// made in the engine itself is overwritten. key, derived from EasyRMM's
// secret key, keys the digest of the mail server given that EasyRMM's
// servers compare theirs with (mail_engine_given); every server has the
// same.
func Mail(source func(context.Context) (MailConfig, error), key []byte) EngineOption {
	return func(e *engine) { e.mail, e.mailKey = source, key }
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

// unchanged is the engine's mail settings m as they are, the password kept
// (none sent), with the webhook switch set to allow.
func (m MailSettings) unchanged(allow bool) MailSettingsInput {
	return MailSettingsInput{SMTPHost: m.SMTPHost, SMTPPort: m.SMTPPort, SMTPSecurity: m.SMTPSecurity, SMTPUsername: m.SMTPUsername,
		FromAddress: m.FromAddress, FromName: m.FromName, SMTPSkipCertificateCheck: m.SMTPSkipCertificateCheck, AllowPrivateNetworkWebhooks: allow}
}

// mailFailLimit is how many reconcile passes in a row may fail to give the
// engine EasyRMM's mail server before the engine's is removed, so that it
// does not go on sending through one EasyRMM may no longer have.
const mailFailLimit = 3

// mailCallTimeout bounds each call to the engine made holding mailLock, so
// that an engine that does not answer holds a request, or a pass, for
// seconds, not as long as the client would wait.
const mailCallTimeout = 10 * time.Second

// lockEngineMail is the advisory lock whose holder, among EasyRMM's
// servers, gives the engine its mail server.
const lockEngineMail = 4471209853362

// lockEngineMailChange is the advisory lock each of EasyRMM's servers
// holds, for a transaction, while it reads and then changes the engine's
// mail settings, so that no two such changes interleave.
const lockEngineMailChange = 4471209853363

// changeEngineMail runs f, which reads and then changes the engine's mail
// settings, holding lockEngineMailChange across EasyRMM's servers. f
// reaches nothing in the database, so one connection is held at a time;
// its calls to the engine are bounded (mailTimeout), and so is how long
// it holds the lock.
func (s *Service) changeEngineMail(ctx context.Context, f func() error) error {
	if s.db == nil {
		return f()
	}
	return s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockEngineMailChange)); err != nil {
			return err
		}
		return f()
	})
}

// lockMail takes mailLock, or gives up when ctx ends.
func (e *engine) lockMail(ctx context.Context) error {
	select {
	case e.mailLock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *engine) unlockMail() { <-e.mailLock }

// mailSettings reads the engine's mail settings, within mailTimeout.
func (e *engine) mailSettings(st context.Context, c *Client) (MailSettings, error) {
	ctx, cancel := context.WithTimeout(st, e.mailTimeout)
	defer cancel()
	return c.MailSettings(ctx)
}

// setMailSettings replaces the engine's mail settings, within mailTimeout.
func (e *engine) setMailSettings(st context.Context, c *Client, in MailSettingsInput) error {
	ctx, cancel := context.WithTimeout(st, e.mailTimeout)
	defer cancel()
	return c.SetMailSettings(ctx, in)
}

// mailStatement is EasyRMM's own statement for the engine's mail settings,
// which need a super administrator.
func mailStatement(ctx context.Context) context.Context {
	return WithStatement(ctx, Statement{Subject: ServiceSubject, Name: "EasyRMM", Role: RoleSuperAdmin, AllOrganizations: true})
}

// sameMail reports whether the engine's mail settings are in's, as far as
// the engine shows them: it never shows the password, only whether there
// is one. The engine trims text and keeps blank text as none.
func sameMail(cur MailSettings, in MailSettingsInput) bool {
	t := strings.TrimSpace
	return cur.SMTPHost == t(in.SMTPHost) && cur.SMTPPort == in.SMTPPort && cur.SMTPSecurity == in.SMTPSecurity &&
		cur.SMTPUsername == t(in.SMTPUsername) && cur.FromAddress == t(in.FromAddress) && cur.FromName == t(in.FromName) &&
		cur.SMTPSkipCertificateCheck == in.SMTPSkipCertificateCheck &&
		cur.SMTPPasswordConfigured == (in.SMTPPassword != nil && *in.SMTPPassword != "")
}

// syncMail gives the engine EasyRMM's mail server in force when it is not
// the one last given, or when the engine's differs from it: the engine may
// not be up when EasyRMM starts or when the mail server changes, and its
// mail settings may be changed in the engine, so each pass looks and tries
// until it is done. One of EasyRMM's servers at a time does so, so that
// servers whose mail servers differ do not give the engine theirs in turn;
// the others say when theirs is not the one given (compareMail).
func (s *Service) syncMail(ctx context.Context, c *Client, res *ReconcileResult) {
	e := s.engine
	if e == nil || e.mail == nil {
		return
	}
	if err := e.lockMail(ctx); err != nil {
		res.problem("could not give the patching engine EasyRMM's mail server: %v", err)
		return
	}
	defer e.unlockMail()
	lead, err := s.leadsMail(ctx)
	if err != nil {
		res.problem("could not tell which of EasyRMM's servers gives the patching engine its mail server: %v", err)
		return
	}
	if !lead {
		s.compareMail(ctx)
		return
	}
	cfg, err := e.mail(ctx)
	if err != nil {
		s.mailFailed(ctx, c, res, fmt.Sprintf("could not read EasyRMM's mail server for the patching engine: %v", err))
		return
	}
	if err := s.recordMail(ctx, cfg); err != nil {
		res.problem("could not record the mail server given to the patching engine, which EasyRMM's other servers compare theirs with: %v", err)
	}
	st := mailStatement(ctx)
	given := e.mailGiven != nil && *e.mailGiven == cfg
	changed := false
	err = s.changeEngineMail(ctx, func() error {
		current, err := e.mailSettings(st, c)
		if err != nil {
			return err
		}
		in := cfg.mailSettings(current)
		if given && sameMail(current, in) {
			return nil
		}
		changed = true
		return e.setMailSettings(st, c, in)
	})
	if err != nil {
		s.mailFailed(ctx, c, res, fmt.Sprintf("could not give the patching engine EasyRMM's mail server: %v", err))
		return
	}
	s.mailSucceeded()
	if !changed {
		return
	}
	e.mailGiven = &cfg
	switch {
	case given:
		s.log.Warn("patching: the engine's mail settings were changed in the engine; EasyRMM gave it its own mail server again", "host", cfg.Host)
	case cfg.Host == "":
		s.log.Info("patching: the engine has no mail server, as EasyRMM has none")
	default:
		s.log.Info("patching: the engine sends email and reports through EasyRMM's mail server", "host", cfg.Host)
	}
}

// leadsMail reports whether this server gives the engine its mail server.
// A server that does not forgets what it gave, so that it gives it again
// should it lead again. Call it with mailLock held.
func (s *Service) leadsMail(ctx context.Context) (bool, error) {
	e := s.engine
	if e.mailLeader == nil {
		return true, nil
	}
	lead, err := e.mailLeader.Lead(ctx)
	switch {
	case err != nil:
		return false, err
	case lead:
		e.mailCompared = nil
	default:
		e.mailGiven, e.mailRecorded, e.mailFailures = nil, nil, 0
	}
	return lead, nil
}

// stopLeadingMail gives up giving the engine its mail server, if this
// server does.
func (s *Service) stopLeadingMail() {
	if e := s.engine; e != nil && e.mailLeader != nil {
		e.mailLeader.Close()
	}
}

// mailDigest is an HMAC-SHA-256 of cfg, keyed by key, which is derived
// from EasyRMM's secret key, so that EasyRMM's servers can tell whether
// theirs is the mail server given to the engine without the mail server
// being stored, and without someone who can read the database being able
// to guess its password from the digest.
func mailDigest(cfg MailConfig, key []byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, f := range []string{strings.ToLower(cfg.Host), strconv.Itoa(cfg.Port), cfg.Security, cfg.Username, cfg.Password, cfg.FromAddress, cfg.FromName} {
		fmt.Fprintf(m, "%d:%s;", len(f), f)
	}
	return m.Sum(nil)
}

// recordMail records cfg as the mail server given to the engine, as a
// digest, when it is not the one last recorded. Call it with mailLock held.
func (s *Service) recordMail(ctx context.Context, cfg MailConfig) error {
	e := s.engine
	if s.db == nil || (e.mailRecorded != nil && *e.mailRecorded == cfg) {
		return nil
	}
	digest := mailDigest(cfg, e.mailKey)
	if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO mail_engine_given (id, digest) VALUES (true, $1)
			ON CONFLICT (id) DO UPDATE SET digest = excluded.digest, given_at = clock_timestamp()`, digest)
		return err
	}); err != nil {
		return err
	}
	e.mailRecorded = &cfg
	return nil
}

// mailComparison is a mail server compared with the record of the one
// given to the engine, and whether it was the same.
type mailComparison struct {
	digest string
	cfg    MailConfig
	same   bool
}

// mailDiffers is why a server's mail server is not the engine's.
const mailDiffers = "This server's mail server (EASYRMM_SMTP_* in .env, or the console's) is not the one another of EasyRMM's servers gives the patching engine, which keeps that one. Give every server the same EASYRMM_SMTP_* settings in .env."

// compareMail, on a server that does not give the engine its mail server,
// says when its own is not the one given: an error in the log once per
// change, of either, and the reason on Settings → Patching. Call it with
// mailLock held.
func (s *Service) compareMail(ctx context.Context) {
	e := s.engine
	cfg, err := e.mail(ctx)
	if err != nil || s.db == nil {
		return
	}
	var digest []byte
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT digest FROM mail_engine_given`).Scan(&digest)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return
	}
	if err != nil {
		s.log.Warn("patching: could not read the mail server given to the engine, to compare this server's with it", "error", err)
		return
	}
	last := e.mailCompared
	if last != nil && last.digest == string(digest) && last.cfg == cfg {
		return
	}
	same := hmac.Equal(mailDigest(cfg, e.mailKey), digest)
	e.mailCompared = &mailComparison{digest: string(digest), cfg: cfg, same: same}
	e.mu.Lock()
	if same {
		e.mailProblem = ""
	} else {
		e.mailProblem = mailDiffers
	}
	e.mu.Unlock()
	switch {
	case !same:
		s.log.Error("patching: "+mailDiffers, "host", cfg.Host)
	case last != nil && !last.same:
		s.log.Info("patching: this server's mail server is the one the patching engine was given again", "host", cfg.Host)
	}
}

// mailFailed notes a pass that could not give the engine EasyRMM's mail
// server. Once mailFailLimit passes in a row have failed, each removes the
// engine's mail server if it can, so that the engine does not go on
// sending through one EasyRMM may no longer have, and the console shows
// why (MailView.Problem). Call it with mailLock held.
func (s *Service) mailFailed(ctx context.Context, c *Client, res *ReconcileResult, problem string) {
	e := s.engine
	res.problem("%s", problem)
	e.mailFailures++
	if e.mailFailures < mailFailLimit {
		return
	}
	e.mu.Lock()
	first := e.mailProblem == ""
	e.mailProblem = problem
	e.mu.Unlock()
	st := mailStatement(ctx)
	removed := false
	err := s.changeEngineMail(ctx, func() error {
		current, err := e.mailSettings(st, c)
		if err != nil {
			return err
		}
		none := MailConfig{}.mailSettings(current)
		if sameMail(current, none) {
			return nil
		}
		removed = true
		return e.setMailSettings(st, c, none)
	})
	if err != nil {
		if first {
			s.log.Error("patching: could not give the engine EasyRMM's mail server, nor remove its own", "problem", problem, "error", err)
		}
		return
	}
	if !removed {
		return
	}
	e.mailGiven = &MailConfig{}
	s.log.Error("patching: could not give the engine EasyRMM's mail server; its own is removed until EasyRMM's can be given, so it sends no email or reports",
		"passes", e.mailFailures, "problem", problem)
}

// mailSucceeded notes a pass that left the engine with EasyRMM's mail
// server. Call it with mailLock held.
func (s *Service) mailSucceeded() {
	e := s.engine
	e.mailFailures = 0
	e.mu.Lock()
	e.mailProblem = ""
	e.mu.Unlock()
}

// mailProblem says why the engine does not have this server's mail
// server; "" when it does.
func (s *Service) mailProblem() string {
	if s.engine == nil {
		return ""
	}
	s.engine.mu.Lock()
	defer s.engine.mu.Unlock()
	return s.engine.mailProblem
}

// UseEngine has the service use the patching engine through c
// (NewEngineClient). Call it before use.
func (s *Service) UseEngine(c *Client, opts ...EngineOption) error {
	if c == nil {
		return apperr.Invalid("engine", "no engine client")
	}
	e := &engine{client: c, mailLock: make(chan struct{}, 1), mailTimeout: mailCallTimeout}
	if s.db != nil {
		e.mailLeader = s.db.Leader(lockEngineMail)
	}
	for _, o := range opts {
		o(e)
	}
	if e.mail != nil && s.db != nil && len(e.mailKey) < 32 {
		return errors.New("easypatch: the mail digest key must be at least 32 bytes")
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
