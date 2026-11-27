// Package app assembles the server: database, services, HTTP routes, the
// TLS edge, the health endpoint and background maintenance.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agentchannel"
	"github.com/paulmataruso/easyrmm/server/internal/agentfiles"
	"github.com/paulmataruso/easyrmm/server/internal/agentlogs"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/agentsettings"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auditfwd"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	calerts "github.com/paulmataruso/easyrmm/server/internal/compliance/alerts"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/engine"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/fix"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/defenderlog"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/docs"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/hardware"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/adapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentfilesapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentlogsapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentsettingsapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentupdatesapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/alertsapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/auditapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/auditfwdapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/authapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/backupapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/complianceapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/defenderapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/devicesapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/docsapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/easypatchapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/enrollapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/gpoapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/hardwareapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/inventoryapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/jobsapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/keystoreapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/mailserverapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/modreadapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/modulesapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/notifyapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/postureapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/quickassistapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/rdpcredsapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/remoteapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/removalapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/repairsapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/reportsapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/ssoapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/tenancyapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/tlsapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/tlstrustapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/usersapi"
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/mailserver"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/modsnap"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/notify"
	"github.com/paulmataruso/easyrmm/server/internal/pki"
	"github.com/paulmataruso/easyrmm/server/internal/posture"
	"github.com/paulmataruso/easyrmm/server/internal/quickassist"
	"github.com/paulmataruso/easyrmm/server/internal/rdpcreds"
	"github.com/paulmataruso/easyrmm/server/internal/recovery"
	"github.com/paulmataruso/easyrmm/server/internal/remote"
	"github.com/paulmataruso/easyrmm/server/internal/reports"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/sso"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
	"github.com/paulmataruso/easyrmm/server/internal/updater"
	"github.com/paulmataruso/easyrmm/server/internal/users"
	"github.com/paulmataruso/easyrmm/server/internal/webui"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/activedirectory"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/backup"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/bitlocker"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/defender"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/grouppolicy"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/grouppolicy/gpowire"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/roles"
)

// Version is set at build time with -ldflags.
var Version = "dev"

// NewLogger builds the process logger from configuration.
func NewLogger(format, level string) *slog.Logger {
	var lv slog.Level
	_ = lv.UnmarshalText([]byte(level))
	opts := &slog.HandlerOptions{Level: lv}
	if format == "text" {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts))
}

// Deps are the assembled services, exposed for tests.
type Deps struct {
	DB       *database.DB
	Audit    *audit.Logger
	Auth     *auth.Service
	Sessions *httpapi.Sessions
	Tenancy  *tenancy.Service
	// Docs keeps the customer record's contacts and places (ADR-0066).
	Docs    *docs.Service
	Users   *users.Service
	Setup   *usersapi.Setup
	Devices *devices.Service
	Agents  *agents.Service
	// JobKeys is the ring of job keys (ADR-0057).
	JobKeys *jobkeys.Ring
	// AgentFiles is the hash list of everything installed (ADR-0070).
	AgentFiles *agentfiles.Service
	// Jobs is the script library and job delivery (ADR-0017).
	Jobs *jobs.Service
	// Inventory stores devices' inventory and metrics (ADR-0018).
	Inventory *inventory.Service
	// Hardware stores devices' disk health (ADR-0065).
	Hardware *hardware.Service
	// Compliance is the compliance engine: control library, packs and scans
	// (ADR-0078).
	Compliance *engine.Service
	// ComplianceFix is the compliance fix queue (ADR-0078, slice C2).
	ComplianceFix *fix.Service
	// ComplianceAssess is the assessment workspace (ADR-0078, slice C5).
	ComplianceAssess *assess.Service
	// Posture is endpoint security posture (ADR-0082), and ComplianceAlerts the
	// two compliance alerts.
	Posture          *posture.Service
	ComplianceAlerts *calerts.Service
	// AgentLogs stores agents' log records (ADR-0069).
	AgentLogs *agentlogs.Service
	// Modules is the Windows management framework: roles and toggles
	// (ADR-0073).
	Modules *modules.Service
	// AgentChannel is the agents' WebSocket channel; off unless
	// EASYRMM_AGENT_CHANNEL is on (ADR-0059).
	AgentChannel *agentchannel.Hub
	// Monitoring evaluates alert policies and keeps alerts (ADR-0019).
	Monitoring *monitoring.Service
	// ModSnap keeps the Windows modules' snapshots (ADR-0073).
	ModSnap     *modsnap.Service
	GroupPolicy *grouppolicy.Service
	// DefenderLog stores the Defender events agents send (ADR-0074).
	DefenderLog *defenderlog.Store
	// Recovery repairs agents that stopped working (ADR-0069).
	Recovery *recovery.Service
	// Reports reads devices, software and alerts into tables (ADR-0029).
	Reports  *reports.Service
	AuditFwd *auditfwd.Service
	// Mail is the mail server: .env's or the console's, its limits and
	// account mail (ADR-0053).
	Mail *mailserver.Service
	// EasyPatch connects patching to an EasyPatch server (ADR-0030).
	EasyPatch *easypatch.Service
	// SSO is single sign-on with OpenID Connect (ADR-0034).
	SSO *sso.Service
	// AgentBuilds are the agent binaries the server hands out.
	AgentBuilds *agents.Builds
	// PKI is the internal certificate authority, for addresses no public CA
	// can certify (ADR-0016); nil when no address uses it.
	PKI *pki.Authority

	// Remote access; nil when it is disabled.
	Mesh        *meshcentral.Client
	Remote      *remote.Service
	Gateway     *remote.Gateway
	MeshSecrets *remote.Secrets
	// RDPCreds keeps the RDP credentials people save per device (ADR-0079).
	RDPCreds *rdpcreds.Service
	// QuickAssist is ad-hoc support sessions (ADR-0080).
	QuickAssist *quickassist.Service
	// Keystore stores the recovery keys agents escrow and has the keystore
	// process check them (ADR-0081); it holds no key.
	Keystore *keystore.Service
	// AgentSettings holds what operators set for agents (ADR-0058).
	AgentSettings *agentsettings.Service
	// TLSTrust asks agents to verify the certificate chains the edge serves
	// and keeps their answers (ADR-0055, slice 5b1).
	TLSTrust *tlstrust.Service
	// Notify is the one notification sender: channels, the outbox, notices
	// (ADR-0053).
	Notify *notify.Service
	// TLS obtains and renews the certificates of the DNS names in acme mode
	// (ADR-0055); nil in the other modes.
	TLS *tlscert.Service
}

// Build constructs the services over an open database.
func Build(ctx context.Context, cfg *config.Config, db *database.DB, log *slog.Logger) (*Deps, error) {
	sealer, err := secrets.NewSealer(cfg.SecretKeys...)
	if err != nil {
		return nil, err
	}
	auditLog := audit.New(db, time.Now)
	mailSvc, err := newMail(db, auditLog, sealer, cfg.SMTP, log)
	if err != nil {
		return nil, err
	}
	hasher := auth.NewHasher(auth.DefaultArgon2Params, cfg.ArgonMaxParallel)
	ac := auth.DefaultConfig()
	ac.RequireMFA = cfg.RequireMFA
	ac.IdleTimeout = cfg.SessionIdle
	ac.MaxSessionAge = cfg.SessionMaxAge
	ac.PasswordResetTTL = cfg.PasswordResetTTL
	ac.PublicURL = cfg.PublicURL.String()
	ac.Issuer = "EasyRMM (" + cfg.PublicURL.Hostname() + ")"
	authSvc := auth.NewService(db, auditLog, hasher, sealer, mailSvc, ac)
	authSvc.SetLogger(log)
	var consoles []string
	for _, o := range cfg.Origins() {
		consoles = append(consoles, originString(o.Console))
	}
	sessions, err := httpapi.NewSessions(authSvc, cfg.SecretKeys[0].Raw, consoles, !cfg.DevInsecureCookie)
	if err != nil {
		return nil, err
	}
	usersSvc := users.New(db, auditLog, authSvc, hasher)
	// With Authentik, before the first-run page could offer itself (ADR-0044).
	if err := firstAdministrator(ctx, cfg, usersSvc, log); err != nil {
		return nil, err
	}
	setup, err := usersapi.NewSetup(ctx, usersSvc, cfg.DataDir, log)
	if err != nil {
		return nil, err
	}
	d := &Deps{
		DB: db, Audit: auditLog, Auth: authSvc, Sessions: sessions,
		Tenancy: tenancy.New(db, auditLog), Docs: docs.New(db, auditLog), Users: usersSvc, Setup: setup, Mail: mailSvc,
	}
	if cfg.NeedsInternalCA() {
		ca, err := pki.Load(ctx, db, sealer)
		if err != nil {
			return nil, err
		}
		names, ips := internalAddresses(cfg)
		if err := ca.SetAddresses(ctx, names, ips); err != nil {
			return nil, err
		}
		d.PKI = ca
	}
	var mesh agents.MeshAgents
	if cfg.Mesh.Enabled {
		if err := buildRemote(ctx, cfg, d, sealer, log); err != nil {
			return nil, err
		}
		files, err := meshcentral.NewFiles(cfg.Mesh.InternalURL.String(), d.MeshSecrets.LoginKey)
		if err != nil {
			return nil, err
		}
		mesh = remote.NewMeshAgents(d.Remote, files)
	}
	d.Devices = devices.New(db, cfg.Mesh.Enabled)
	d.Devices.SetAudit(auditLog)
	if d.Remote != nil {
		d.Devices.OnMoved(d.Remote.DevicesChanged)
	}
	d.Agents = agents.New(db, auditLog, mesh, log)
	d.Agents.SetSealer(sealer)
	// The ring of job keys (ADR-0057): the first start with it moves the key
	// out of settings; every service asks it for the key that signs each
	// device's instruction.
	ring, err := jobkeys.Open(ctx, db, sealer, log, jobkeys.Options{Version: Version, Audit: auditLog})
	if err != nil {
		return nil, err
	}
	d.JobKeys = ring
	d.Jobs = jobs.New(db, auditLog, ring, cfg.JobRetention, cfg.JobOutputRetention, log)
	d.Agents.SetKeys(ring)
	d.Compliance = engine.New(db, d.Jobs, auditLog, log)
	// A hardening change of tier 3 needs the session stepped up (ADR-0055).
	d.Jobs.SetStepUp(sessions)
	if d.ComplianceFix, err = fix.New(db, d.Jobs, d.Compliance, auditLog, log); err != nil {
		return nil, err
	}
	d.ComplianceFix.SetStepUp(sessions)
	d.ComplianceAssess = assess.New(db, auditLog, sealer, log)
	d.ComplianceAssess.SetStepUp(sessions)
	d.ComplianceAlerts = calerts.New(db, log)
	d.AgentChannel = agentchannel.New(agentchannel.Options{
		Enabled: cfg.AgentChannel, Key: ring.Newest().Private, Instance: uuid.NewString(), MaxConns: cfg.AgentConnectionsMax,
		Timing: agentchannel.Timing{ConfirmWithin: 2 * agents.HeartbeatInterval}, Log: log,
	})
	d.Agents.OnDeviceGone(func(id uuid.UUID) { d.AgentChannel.Close(id, agentproto.ClosingRemoved) })
	d.QuickAssist = quickassist.New(db, auditLog, ring.Newest().Private, strings.TrimSuffix(cfg.PublicURL.String(), "/"))
	d.QuickAssist.OnThrottled(quickAssistFlood(db, mailSvc, log))
	if d.Mesh != nil {
		d.QuickAssist.SetNodeRemover(d.Mesh.RemoveDevice)
	}
	d.Inventory = inventory.New(db, cfg.MetricsRetention, log)
	d.Hardware = hardware.New(db, cfg.MetricsRetention, cfg.HardwareRetention, log)
	d.AgentLogs = agentlogs.New(db, auditLog, cfg.AgentLogRetentionDays, log)
	d.Modules = modules.New(db, auditLog, log)
	d.Agents.SetRoleStore(d.Modules)
	// The winmod job kind runs the catalog's actions where the module is
	// on (ADR-0073, slice 5).
	catalog, err := winmod.NewCatalog(slices.Concat(defender.Actions(), backup.Actions(), roles.Actions(), bitlocker.Actions())...)
	if err != nil {
		return nil, err
	}
	d.Jobs.SetWinmod(catalog, d.Modules, sealer)
	// Group Policy (ADR-0083): its backups, approvals and the gate that checks them.
	d.GroupPolicy = gpowire.New(db, auditLog, d.Modules, catalog, d.Jobs)
	d.Monitoring = monitoring.New(db, auditLog, cfg.AlertRetention, cfg.MetricsRetention, log)
	// Snapshots and module alerts (ADR-0073, slices 6 and 7): a role that
	// goes clears the module's snapshots and resolves its alerts; a module
	// turned on gets its default policies.
	if err := monitoring.RegisterModuleAlerts(defender.AlertKinds()); err != nil {
		return nil, err
	}
	if err := monitoring.RegisterModuleAlerts(backup.AlertKinds()); err != nil {
		return nil, err
	}
	if err := roles.Register(); err != nil {
		return nil, err
	}
	d.ModSnap = modsnap.New(db, catalog, d.Modules, d.Modules, d.Jobs, log)
	d.Modules.OnRoleRemoved(modsnap.OnRoleRemoved)
	d.Modules.OnRoleRemoved(monitoring.RoleRemovedHook)
	d.Modules.OnEnabled(monitoring.EnsureDefaults)
	d.Monitoring.UseModules(d.Modules)
	d.DefenderLog = defenderlog.New(db, d.Modules, log)
	d.Agents.SetDefenderLog(d.DefenderLog)
	d.Recovery = recovery.New(db, auditLog, cfg.Mesh.Enabled, log)
	if d.Mesh != nil {
		// Nothing about remote access is judged while EasyRMM cannot see
		// MeshCentral, or for a while after it can (ADR-0069).
		d.Monitoring.FollowMesh(d.Mesh.Session)
		d.Recovery.FollowMesh(d.Mesh.Session)
	}
	d.Reports = reports.New(db, auditLog)
	d.AuditFwd = auditfwd.New(db, auditLog, sealer, cfg.PublicURL.Hostname(), Version, log)
	d.EasyPatch = easypatch.New(db, auditLog, Version, log)
	// A removed device's EasyPatch agent is told to uninstall itself at once,
	// not at the next reconcile pass (ADR-0050).
	d.Agents.OnRemoved(d.EasyPatch.Kick)
	// The patch reports read patching through it.
	d.Reports.UsePatching(d.EasyPatch)
	d.Posture = posture.New(db, d.EasyPatch, log)
	if err := usePatchingEngine(cfg, d, sealer, log); err != nil {
		return nil, err
	}
	d.SSO = sso.New(db, auditLog, sealer, d.Auth, cfg.PublicURL)
	if err := useAuthentik(ctx, cfg, d.SSO, d.PKI); err != nil {
		return nil, fmt.Errorf("authentik: %w", err)
	}
	d.EasyPatch.SetSigner(ring)
	d.Recovery.SetKey(ring)
	// The EasyPatch agent is repaired with packages from the engine, and
	// judged by what the engine reports of it (ADR-0069).
	d.Recovery.UsePatching(d.EasyPatch)
	builds, err := agents.LoadBuilds(cfg.AgentDir)
	if err != nil {
		return nil, err
	}
	if len(builds.List()) == 0 {
		log.Warn("no EasyRMM agent builds found; the console cannot offer agent downloads", "dir", cfg.AgentDir)
	}
	d.AgentBuilds = builds
	if len(builds.List()) > 0 && builds.Version() == "" {
		log.Warn("the agent builds have no "+agents.VersionFile+" file; agent updates still work, but the console cannot show versions", "dir", cfg.AgentDir)
	}
	d.Agents.SetUpdates(builds, ring)
	// The dev scope (development only): organizations outside it keep the
	// stable builds. A server that cannot offer them does not start.
	devscope.Set(cfg.DevScopeOrg)
	if devscope.Active() {
		stable, err := loadStable(cfg.AgentStableDir)
		if err != nil {
			return nil, err
		}
		d.Agents.SetStable(stable)
	}
	devscope.Log(log)
	// Windows builds an operator signed take the release's place (ADR-0049).
	if err := d.Agents.LoadSignedBuilds(ctx); err != nil {
		return nil, err
	}
	d.Devices.SetBuilds(d.Agents.BuildLookup)
	d.Recovery.SetBuilds(d.Agents.ReleaseHashes)
	d.wireChannel()
	// The hash list of everything the server hands out or installs, kept
	// current: on start, on a signed build, on a new agent version, on a
	// timer (ADR-0070). Where the development scope takes effect: see
	// agents.DefenderScope.
	d.Agents.SetDefenderScope(agents.ScopeFunc(devscope.Allowed))
	var ks keystore.Verifier
	if cfg.KeystoreSocket != "" {
		ks = &keystore.Client{Path: cfg.KeystoreSocket}
	}
	d.Keystore = keystore.New(db, auditLog, ks, ring, log)
	d.AgentSettings = agentsettings.New(db, auditLog, log)
	d.TLSTrust = tlstrust.New(db, auditLog, ring, log)
	d.TLSTrust.SetEasyPatchHost(easyPatchHost(db, cfg.PublicURL))
	// Reading a key needs the session stepped up (ADR-0055) and mails the
	// organization's administrators (ADR-0053).
	d.Keystore.SetStepUp(sessions)
	d.Keystore.SetNotifier(mailSvc)
	d.Notify = newNotify(cfg, db, auditLog, sealer, mailSvc, log)
	if cfg.TLSMode == config.TLSAcme {
		d.TLS = newTLS(cfg, db, auditLog, sealer, d.Notify, log)
	}
	// BitLocker's enable action asks the keystore's gate before it makes a job.
	d.Jobs.SetEscrowGate(d.Keystore)
	var files agentfiles.Mesh
	if mesh != nil {
		files = mesh
	}
	d.AgentFiles = agentfiles.New(db, log, builds, files, d.EasyPatch)
	d.Agents.OnServedBuildsChanged(func() { go d.AgentFiles.ServedChanged(context.WithoutCancel(ctx)) })
	d.Agents.OnAgentVersion(func(v string) { go d.AgentFiles.VersionReported(v) })
	return d, nil
}

// loadStable loads the stable agent builds the dev scope needs: a server that
// cannot offer them, a missing or empty directory, does not start.
func loadStable(dir string) (*agents.Builds, error) {
	stable, err := agents.LoadBuilds(dir)
	if err != nil {
		return nil, fmt.Errorf("EASYRMM_DEV_SCOPE_ORG is set, so the stable agent builds are needed: %w", err)
	}
	if len(stable.List()) == 0 {
		return nil, fmt.Errorf("EASYRMM_DEV_SCOPE_ORG is set, but EASYRMM_AGENT_STABLE_DIR (%s) holds no agent builds: organizations outside the scope would get none", dir)
	}
	return stable, nil
}

// buildRemote assembles the MeshCentral integration.
// usePatchingEngine gives d.EasyPatch the patching engine in this
// deployment, on loopback (ADR-0038).
func usePatchingEngine(cfg *config.Config, d *Deps, sealer *secrets.Sealer, log *slog.Logger) error {
	p := cfg.Patching
	signer, err := easypatch.NewSigner(p.Key)
	if err != nil {
		return err
	}
	engine, err := easypatch.NewEngineClient(p.URL, signer, Version)
	if err != nil {
		return err
	}
	var opts []easypatch.EngineOption
	if cfg.TLSMode == config.TLSInternal && d.PKI != nil {
		// The engine's public address is EasyRMM's, with EasyRMM's own
		// certificate authority: agents are given it (ADR-0042).
		opts = append(opts, easypatch.AgentCA(d.PKI.CAPEM))
	}
	// An imported EasyPatch's agents keep the names they enrolled with.
	if len(p.AgentHostnames) > 0 {
		opts = append(opts, easypatch.AgentHostnames(p.AgentHostnames))
	}
	// The engine emails through EasyRMM's mail server in force, which
	// reaches it within seconds of every change (ADR-0053), unless a
	// Microsoft 365 application signs in to it, which the engine cannot.
	// Its digests, which EasyRMM's servers compare theirs with, are keyed
	// by keys of their own, derived from each secret key.
	mailKeys, err := sealer.DeriveKeys("easyrmm engine mail digest v1")
	if err != nil {
		return err
	}
	opts = append(opts, easypatch.Mail(func(ctx context.Context) (easypatch.MailConfig, error) {
		m, err := d.Mail.InForce(ctx)
		if err != nil || m == nil {
			return easypatch.MailConfig{}, err
		}
		if mailserver.WithholdsFromEngine(m) {
			return easypatch.MailConfig{Withheld: mailserver.EngineWithheld}, nil
		}
		return easypatch.MailConfig{Host: m.Host, Port: m.Port, Username: m.Username, Password: m.Password, FromAddress: m.FromAddress,
			FromName: m.FromName, Security: m.Security}, nil
	}, mailKeys))
	if err := d.EasyPatch.UseEngine(engine, opts...); err != nil {
		return fmt.Errorf("patching engine: %w", err)
	}
	log.Info("patching: the engine in this deployment", "url", p.URL)
	// Organization and site changes reach the engine within seconds
	// (ADR-0040), and so do the mail server's.
	d.Tenancy.OnChange(d.EasyPatch.Kick)
	d.Mail.OnChange(d.EasyPatch.Kick)
	return nil
}

// m365Authority is where Microsoft 365 applications ask for tokens:
// Microsoft's identity platform, unless a test sets its stand-in's.
var m365Authority string

// newMail builds the mail server's service: .env's mail server, signing in
// with .env's Microsoft 365 application when it has one, or the console's.
func newMail(db *database.DB, auditLog *audit.Logger, sealer *secrets.Sealer, c config.SMTPConfig, log *slog.Logger) (*mailserver.Service, error) {
	app, err := c.SMTPApplication()
	if err != nil {
		return nil, fmt.Errorf("EASYRMM_SMTP_*: %w", err)
	}
	var opts []mailserver.Option
	if app != nil {
		opts = append(opts, mailserver.EnvApplication(app))
	}
	if m365Authority != "" {
		opts = append(opts, mailserver.Authority(m365Authority))
	}
	return mailserver.New(db, auditLog, sealer, envMail(c), log, opts...)
}

// MailCheck checks the mail server in force as the running server does and
// prints its answer: it connects and signs in, getting a token first when
// a Microsoft 365 application signs in, and quits without sending.
//
//	docker compose exec server easyrmm-server mail check
func MailCheck(ctx context.Context, cfg *config.Config, log *slog.Logger, out io.Writer) error {
	sealer, err := secrets.NewSealer(cfg.SecretKeys...)
	if err != nil {
		return err
	}
	db, err := database.Open(ctx, cfg.DatabaseURL, database.PoolOptions{MaxConns: 2, Version: Version})
	if err != nil {
		return err
	}
	defer db.Close()
	svc, err := newMail(db, audit.New(db, time.Now), sealer, cfg.SMTP, log)
	if err != nil {
		return err
	}
	answer, err := svc.Check(ctx)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, answer)
	return err
}

// envMail is .env's mail server (EASYRMM_SMTP_*), nil without
// EASYRMM_SMTP_HOST. EASYRMM_SMTP_FROM may carry a name, as
// "EasyRMM <rmm@example.com>"; EASYRMM_SMTP_TLS calls TLS from the first
// byte implicit.
func envMail(c config.SMTPConfig) *mailer.Config {
	if c.Host == "" {
		return nil
	}
	m := &mailer.Config{Host: c.Host, Port: c.Port, Username: c.Username, Password: c.Password, FromAddress: c.From, Security: c.TLS}
	if a, err := mail.ParseAddress(c.From); err == nil {
		m.FromAddress, m.FromName = a.Address, a.Name
	}
	if c.TLS == "implicit" {
		m.Security = mailer.TLS
	}
	return m
}

func buildRemote(ctx context.Context, cfg *config.Config, d *Deps, sealer *secrets.Sealer, log *slog.Logger) error {
	sec, err := remote.LoadSecrets(ctx, d.DB, sealer)
	if err != nil {
		return err
	}
	var svc *remote.Service
	client, err := meshcentral.NewClient(meshcentral.ClientOptions{
		BaseURL: cfg.Mesh.InternalURL.String(),
		Key:     sec.LoginKey,
		Log:     log,
		OnEvent: func(ev meshcentral.Event) { svc.HandleEvent(ev) },
		OnReady: func() { svc.Changed() },
	})
	if err != nil {
		return err
	}
	svc = remote.New(d.DB, d.Audit, client, remote.Config{MeshURL: cfg.MeshPublicURL, LoginKey: sec.LoginKey, DiscoveryGrace: remote.DefaultDiscoveryGrace}, log)
	gw, err := remote.NewGateway(svc, remote.GatewayConfig{Upstream: cfg.Mesh.InternalURL, Secure: !cfg.DevInsecureCookie}, log)
	if err != nil {
		return err
	}
	d.RDPCreds = rdpcreds.New(d.DB, d.Audit, sealer, d.Auth.LoadPrincipal)
	gw.SetCredentialOpener(rdpOpener{d.RDPCreds})
	d.Tenancy.OnChange(svc.Changed)
	d.Users.OnChange(svc.Changed)
	d.Mesh, d.Remote, d.Gateway, d.MeshSecrets = client, svc, gw, sec
	return nil
}

// MeshServerConfig is the MeshCentral configuration EasyRMM writes.
func MeshServerConfig(cfg *config.Config, sec *remote.Secrets) meshcentral.ServerConfig {
	port := 443
	if p := cfg.MeshPublicURL.Port(); p != "" {
		port, _ = strconv.Atoi(p)
	}
	// Written on every start from the origins served then: a change in them
	// (IP access, the addresses) changes the file, and MeshCentral's start
	// script then restarts MeshCentral.
	var framing, mesh []string
	for _, o := range cfg.Origins() {
		framing = append(framing, originString(o.Console))
		if o.Mesh != nil {
			mesh = append(mesh, originString(o.Mesh))
		}
	}
	return meshcentral.ServerConfig{
		Hostname:       cfg.MeshPublicURL.Hostname(),
		Listen:         cfg.Mesh.InternalURL.Host,
		PublicPort:     port,
		TrustedProxy:   cfg.Mesh.InternalURL.Hostname(),
		FramingOrigins: framing,
		MeshOrigins:    mesh,
		CertURL:        cfg.Mesh.CertURL,
		LoginKey:       sec.LoginKey,
		SessionKey:     sec.SessionKey,
	}
}

// writeMeshConfig writes MeshCentral's config.json and the files its pages
// load from EasyRMM (ADR-0025). MeshCentral's start script restarts it when
// config.json changes; the web files are written first, so they are there
// when it does.
func writeMeshConfig(cfg *config.Config, sec *remote.Secrets, log *slog.Logger) error {
	content, err := MeshServerConfig(cfg, sec).Render()
	if err != nil {
		return err
	}
	web, err := meshcentral.WriteWeb(cfg.Mesh.ConfigDir)
	if err != nil {
		return err
	}
	if web {
		log.Info("wrote MeshCentral session view tuning", "dir", cfg.Mesh.ConfigDir)
	}
	changed, err := meshcentral.WriteConfig(cfg.Mesh.ConfigDir, content)
	if err != nil {
		return err
	}
	if changed {
		log.Info("wrote MeshCentral configuration", "dir", cfg.Mesh.ConfigDir)
	}
	return nil
}

// Handler builds the complete HTTP handler for every origin: the console
// and agent API on the public URL and, with IP access, on each IP address;
// the MeshCentral gateway on the matching MeshCentral origins.
func Handler(cfg *config.Config, d *Deps, log *slog.Logger) (http.Handler, error) {
	all := origins(cfg, d.PKI, d.Gateway != nil)
	var addresses []enrollapi.Address
	var agentAddresses []agentapi.Address
	var frames []string
	for _, o := range all {
		addresses = append(addresses, enrollapi.Address{URL: o.Console, Pin: o.Pin, KeyPin: o.KeyPin})
		agentAddresses = append(agentAddresses, agentapi.Address{URL: o.Console, Pin: o.Pin, KeyPin: o.KeyPin})
		if o.Mesh != "" {
			frames = append(frames, o.Mesh)
		}
	}
	var caPEM []byte
	var caInfo *enrollapi.Authority
	if d.PKI != nil {
		caPEM = d.PKI.CAPEM()
		caInfo = &enrollapi.Authority{Fingerprint: d.PKI.Fingerprint(), URL: agentproto.PathCA, CertURL: agentproto.PathCACert}
	}

	mux := http.NewServeMux()
	authapi.New(d.Auth, d.Sessions, authapi.Features{RemoteAccess: d.Remote != nil}).Register(mux)
	tenancyapi.New(d.Tenancy).Register(mux)
	docsapi.New(d.Docs).Register(mux)
	devicesapi.New(d.Devices).Register(mux)
	enrollapi.New(d.Agents, d.AgentBuilds, cfg.PublicURL.String(), addresses, caInfo).Register(mux)
	if d.Remote != nil {
		remoteapi.New(d.Remote).WithStepUp(d.Sessions).Register(mux)
		rdpcredsapi.New(d.RDPCreds, d.Sessions).Register(mux)
	}
	quickassistapi.New(d.QuickAssist, d.Sessions, d.AgentBuilds).Register(mux)
	usersapi.New(d.Users, d.Setup).Register(mux)
	auditapi.New(d.Audit).Register(mux)
	jobsapi.New(d.Jobs).Register(mux)
	modreadapi.New(d.ModSnap).Register(mux)
	inventoryapi.New(d.Inventory).Register(mux)
	hardwareapi.New(d.Hardware).Register(mux)
	tlstrustapi.New(d.TLSTrust).Register(mux)
	complianceapi.New(d.Compliance, d.ComplianceFix, d.ComplianceAssess).Register(mux)
	postureapi.New(d.Posture).Register(mux)
	agentlogsapi.New(d.AgentLogs).Register(mux)
	modulesapi.New(d.Modules).Register(mux)
	defenderapi.New(d.DefenderLog, d.Modules).Register(mux)
	backupapi.New(backup.NewCards(d.DB, d.Modules)).Register(mux)
	adapi.New(activedirectory.New(d.DB, d.Modules, d.Audit)).Register(mux)
	gpoapi.New(d.GroupPolicy).Register(mux)
	alertsapi.New(d.Monitoring).Register(mux)
	reportsapi.New(d.Reports).Register(mux)
	auditfwdapi.New(d.AuditFwd).Register(mux)
	mailserverapi.New(d.Mail).Register(mux)
	tlsapi.New(d.TLS, string(cfg.TLSMode)).Register(mux)
	easypatchapi.New(d.EasyPatch).Register(mux)
	ssoapi.New(d.SSO, d.Sessions, cfg.PublicURL).Register(mux)
	agentupdatesapi.New(d.Agents, d.Devices).Register(mux)
	agentfilesapi.New(d.AgentFiles).Register(mux)
	removalapi.New(d.Agents, d.Devices).Register(mux)
	repairsapi.New(d.Recovery).Register(mux)
	mux.Handle("GET /api/v1/health", httpapi.Handle(func(w http.ResponseWriter, _ *http.Request) error {
		httpapi.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": Version})
		return nil
	}))
	// Unknown API paths get a JSON 404, never the web interface.
	mux.Handle("/api/", httpapi.Handle(func(http.ResponseWriter, *http.Request) error {
		return httpapi.ErrNotFound
	}))
	files, err := webui.FS(cfg.WebDir)
	if err != nil {
		return nil, fmt.Errorf("web interface: %w", err)
	}
	keystoreapi.New(d.Keystore).Register(mux)
	agentsettingsapi.New(d.AgentSettings).Register(mux)
	notifyapi.New(d.Notify).Register(mux)
	mux.Handle("/", webui.Handler(files))

	trusted := cfg.TrustedProxies
	if cfg.TLSMode != config.TLSOffload {
		trusted = nil // nobody sits in front of us
	}
	app := httpapi.Chain(mux,
		httpapi.SecurityHeaders(!cfg.DevInsecureCookie, strings.Join(frames, " ")),
		webui.Announce(webui.Build(files)),
		d.Sessions.Load,
		d.Sessions.CSRF,
	)
	agentAPI, err := agentapi.New(d.Agents, d.AgentBuilds, agentAddresses, caPEM, log)
	if err != nil {
		return nil, err
	}
	agentAPI.WithJobs(d.Jobs).WithInventory(d.Inventory).WithHardware(d.Hardware).WithAgentLogs(d.AgentLogs).WithEasyPatch(d.EasyPatch).WithRepairs(d.Recovery).WithChannel(d.AgentChannel).WithQuickAssist(d.QuickAssist).WithEscrow(d.Keystore).WithTrust(d.TLSTrust)
	// Agents carry no browser session: their routes skip the session and
	// CSRF layers and authenticate every request themselves.
	agentHandler := httpapi.Chain(agentAPI.Handler(), httpapi.SecurityHeaders(!cfg.DevInsecureCookie, ""))
	// EasyPatch agents reach the patching engine in this deployment through
	// EasyRMM's own addresses (ADR-0039).
	target, err := url.Parse(cfg.Patching.URL)
	if err != nil {
		return nil, fmt.Errorf("EASYRMM_PATCHING_URL: %w", err)
	}
	patchingAgents := easypatch.NewAgentProxy(target, !cfg.DevInsecureCookie, log)
	// The names served besides the origins (config.ExtraHostnames): an
	// imported EasyPatch's, for its agents.
	extra := hostHandlers{}
	agentHost := easypatch.AgentHost(patchingAgents, originString(cfg.PublicURL))
	for _, name := range cfg.Patching.AgentHostnames {
		extra[name] = agentHost
	}
	// Authentik's sign-in name (ADR-0044).
	if a := cfg.Authentik; a.Enabled() {
		extra[a.Hostname] = authentikProxy(a.Upstream, !cfg.DevInsecureCookie, log)
	}
	rt := newRouter(all)
	hosts := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m, ok := rt.match(r.Host)
		if !ok {
			if h, ok := extra.match(r.Host); ok {
				h.ServeHTTP(w, r)
				return
			}
			httpapi.WriteError(w, r, &httpapi.Error{Status: http.StatusMisdirectedRequest, Code: "unknown_host", Message: "This server does not serve that address."})
			return
		}
		r = httpapi.WithOrigin(r, m.origin)
		switch {
		case m.mesh:
			// Remote access: agents, and browsers holding a session grant.
			d.Gateway.ServeHTTP(w, r)
		case patchingAgents != nil && easypatch.AgentPath(r.URL.Path):
			// Before the session, CSRF and console layers: an EasyPatch
			// agent carries none of what they check.
			patchingAgents.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, agentproto.PathPrefix):
			agentHandler.ServeHTTP(w, r)
		default:
			app.ServeHTTP(w, r)
		}
	})
	return httpapi.Chain(hosts,
		httpapi.Recover,
		httpapi.RealIP(trusted),
		httpapi.RequestContext(log),
	), nil
}

// Run starts the server and blocks until ctx is canceled.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	log.Info("starting EasyRMM server", "version", Version, "tls_mode", cfg.TLSMode, "public_url", cfg.PublicURL.String())
	if cfg.IPAccess {
		if len(cfg.IPAddresses) == 0 && cfg.TLSMode != config.TLSOffload {
			log.Warn("IP access is on but no IP address was found; set EASYRMM_IP_ADDRESSES")
		}
		for _, o := range cfg.Origins()[1:] {
			log.Info("IP access", "console", originString(o.Console))
		}
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}
	migCfg, err := pgx.ParseConfig(cfg.DatabaseMigrationURL)
	if err != nil {
		return fmt.Errorf("EASYRMM_DATABASE_MIGRATION_URL: %w", err)
	}
	if err := waitFor(ctx, log, "database", func(ctx context.Context) error {
		return database.MigrateWithConfig(ctx, migCfg, log)
	}); err != nil {
		return err
	}
	db, err := database.Open(ctx, cfg.DatabaseURL, database.PoolOptions{MaxConns: cfg.DatabaseMaxConns, Version: Version})
	if err != nil {
		return err
	}
	defer db.Close()

	deps, err := Build(ctx, cfg, db, log)
	if err != nil {
		return err
	}
	if cfg.SMTP.Host != "" {
		log.Info("e-mail: the mail server is EASYRMM_SMTP_HOST's, from .env, which wins over the console", "host", cfg.SMTP.Host)
	} else if !deps.Mail.Available(ctx) {
		log.Info("e-mail: no mail server; until a super administrator sets one under Settings → Notifications → Mail server, password reset is off and administrators deliver invitation links themselves")
	}
	h, err := Handler(cfg, deps, log)
	if err != nil {
		return err
	}
	// The compliance content (ADR-0078): a file the edition may not carry is
	// refused and logged, and the server starts without it.
	if err := deps.Compliance.LoadContent(ctx, content.FS, compliance.Edition); err != nil {
		log.Error("compliance: loading the content failed", "error", err)
	}
	// Read before the listeners open, then followed (ADR-0052). Offline
	// policies count from when the server began serving agents.
	hold := updater.NewHold(cfg.UpdaterStatusDir, log)
	deps.Monitoring.FollowServing(hold.ServingSince)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	wg.Go(func() { hold.Run(ctx) })
	if deps.AgentChannel.Enabled() {
		// A hold ends the agents' connections (restart), and so does stopping.
		deps.AgentChannel.SetHeld(hold.Held)
		wg.Go(func() { deps.AgentChannel.Run(ctx) })
	}
	var tasks []func(context.Context) error
	if deps.Remote != nil {
		if err := writeMeshConfig(cfg, deps.MeshSecrets, log); err != nil {
			// Remote access stays unavailable; everything else works.
			log.Error("remote access: writing the MeshCentral configuration failed", "error", err, "dir", cfg.Mesh.ConfigDir)
		}
		wg.Go(func() { deps.Mesh.Run(ctx) })
		wg.Go(func() { deps.Remote.Run(ctx) })
		wg.Go(func() { deps.Gateway.Run(ctx) })
		tasks = append(tasks, deps.Remote.CleanupGrants)
	} else {
		log.Info("remote access is disabled (EASYRMM_MESH_ENABLED=false)")
	}
	tasks = append(tasks, deps.Agents.Cleanup, deps.Inventory.Purge, deps.Hardware.Purge, deps.AgentLogs.Purge, deps.DefenderLog.Cleanup)
	wg.Go(func() { deps.Agents.Run(ctx) })
	wg.Go(func() { deps.QuickAssist.Run(ctx) })
	wg.Go(func() { deps.AgentFiles.Run(ctx, 30*time.Minute) })
	deps.JobKeys.SetHeld(hold.Held)
	wg.Go(func() { deps.JobKeys.Run(ctx) })
	wg.Go(func() { deps.Jobs.Run(ctx) })
	wg.Go(func() { deps.Compliance.Run(ctx) })
	wg.Go(func() { deps.ComplianceFix.Run(ctx) })
	wg.Go(func() { deps.ComplianceAlerts.Run(ctx) })
	wg.Go(func() { deps.Posture.Run(ctx) })
	wg.Go(func() { deps.Monitoring.Run(ctx) })
	wg.Go(func() { deps.ModSnap.Run(ctx) })
	wg.Go(func() { deps.Recovery.Run(ctx) })
	wg.Go(func() { deps.Keystore.Run(ctx) })
	deps.Notify.SetHeld(hold.Held)
	deps.Notify.SetSeenFloor(deps.Monitoring.SeenFloor)
	wg.Go(func() { deps.Notify.Run(ctx) })
	if deps.TLS != nil {
		deps.TLS.SetHeld(hold.Held)
		// A certificate that cannot be loaded never stops the server from
		// starting: it serves what it has, and the Certificates page and an
		// alert say what is wrong.
		if err := deps.TLS.Start(ctx); err != nil {
			log.Error("tls: the certificate service could not start", "error", err)
		}
		wg.Go(func() { deps.TLS.Run(ctx) })
		defer deps.TLS.Close()
	}
	wg.Go(func() { deps.AuditFwd.Run(ctx) })
	wg.Go(func() { deps.EasyPatch.Run(ctx) })
	wg.Go(func() { deps.EasyPatch.RunAgentPoll(ctx) })
	// The mail server in force: checked at start, after changes and daily,
	// signing in without sending; its answer is logged and in the console.
	wg.Go(func() { deps.Mail.Run(ctx) })
	// Waiting job polls end with the server, not 25 seconds later.
	wg.Go(func() {
		<-ctx.Done()
		deps.Jobs.Close()
		deps.Agents.Close()
	})
	wg.Go(func() { maintain(ctx, db, cfg.AuditRetention, log, tasks...) })
	healthErr := make(chan error, 1)
	if cfg.ListenHealth != "" {
		wg.Go(func() { healthErr <- serveHealth(ctx, cfg.ListenHealth, db, hold, log) })
	}
	e := &edge{cfg: cfg, handler: h, hold: hold, log: log, pki: deps.PKI, tls: deps.TLS, trust: deps.TLSTrust}
	runErr := e.run(ctx)
	cancel()
	wg.Wait()
	// Reset e-mail already accepted is sent before the server exits.
	deps.Auth.Wait()
	if runErr != nil {
		return runErr
	}
	select {
	case err := <-healthErr:
		return err
	default:
		return nil
	}
}

// waitFor retries fn until it succeeds or ctx ends, for dependencies that
// start alongside us (the database container).
func waitFor(ctx context.Context, log *slog.Logger, what string, fn func(context.Context) error) error {
	delay := time.Second
	for attempt := 1; ; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if attempt >= 30 {
			return fmt.Errorf("%s unavailable: %w", what, err)
		}
		log.Warn("waiting for "+what, "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(delay*2, 10*time.Second)
	}
}

// serveHealth serves probes on a loopback address:
// /healthz (process is up) and /readyz (database reachable). They answer
// while the updater holds the server, so that Compose finds it healthy;
// /readyz then says it is held.
func serveHealth(ctx context.Context, addr string, db *database.DB, hold *updater.Hold, log *slog.Logger) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		c, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := db.Ping(c); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		if hold.Held() {
			_, _ = w.Write([]byte("ready, held by the updater\n"))
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := listen(ctx, addr)
	if err != nil {
		return fmt.Errorf("health listener: %w", err)
	}
	log.Info("health endpoint listening", "addr", ln.Addr().String())
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// maintain removes expired sessions and reset tokens hourly and enforces
// audit retention daily.
func maintain(ctx context.Context, db *database.DB, retention time.Duration, log *slog.Logger, tasks ...func(context.Context) error) {
	var lastPurge time.Time
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		if err := Cleanup(ctx, db); err != nil && ctx.Err() == nil {
			log.Error("maintenance: cleanup failed", "error", err)
		}
		for _, t := range tasks {
			if err := t(ctx); err != nil && ctx.Err() == nil {
				log.Error("maintenance: cleanup failed", "error", err)
			}
		}
		if time.Since(lastPurge) >= 24*time.Hour {
			n, err := PurgeAudit(ctx, db, retention)
			if err != nil && ctx.Err() == nil {
				log.Error("maintenance: audit retention failed", "error", err)
			} else if err == nil {
				lastPurge = time.Now()
				if n > 0 {
					log.Info("maintenance: removed audit records past retention", "count", n, "retention", retention.String())
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Cleanup deletes sessions and reset tokens that ended more than a week
// ago. Recently ended sessions are kept so users can review them.
func Cleanup(ctx context.Context, db *database.DB) error {
	return db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now() - interval '7 days'
			OR idle_expires_at < now() - interval '7 days' OR revoked_at < now() - interval '7 days'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE expires_at < now() - interval '1 day'`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM recovery_links WHERE expires_at < now() - interval '1 day'`)
		return err
	})
}

// PurgeAudit removes audit records older than retention.
func PurgeAudit(ctx context.Context, db *database.DB, retention time.Duration) (int64, error) {
	var n int64
	err := db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT easyrmm_purge_audit(make_interval(secs => $1))`, retention.Seconds()).Scan(&n)
	})
	return n, err
}
