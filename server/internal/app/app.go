// Package app assembles the server: database, services, HTTP routes, the
// TLS edge, the health endpoint and background maintenance.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/config"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/agentapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/auditapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/authapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/devicesapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/enrollapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/remoteapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/tenancyapi"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi/usersapi"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/remote"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/tenancy"
	"github.com/paulmataruso/easyrmm/server/internal/users"
	"github.com/paulmataruso/easyrmm/server/internal/webui"
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
	Users    *users.Service
	Setup    *usersapi.Setup
	Devices  *devices.Service
	Agents   *agents.Service
	// AgentBuilds are the agent binaries the server hands out.
	AgentBuilds *agents.Builds

	// Remote access; nil when it is disabled.
	Mesh        *meshcentral.Client
	Remote      *remote.Service
	Gateway     *remote.Gateway
	MeshSecrets *remote.Secrets
}

// Build constructs the services over an open database.
func Build(ctx context.Context, cfg *config.Config, db *database.DB, mail auth.Mailer, log *slog.Logger) (*Deps, error) {
	sealer, err := secrets.NewSealer(cfg.SecretKeys...)
	if err != nil {
		return nil, err
	}
	auditLog := audit.New(db, time.Now)
	hasher := auth.NewHasher(auth.DefaultArgon2Params, cfg.ArgonMaxParallel)
	ac := auth.DefaultConfig()
	ac.RequireMFA = cfg.RequireMFA
	ac.IdleTimeout = cfg.SessionIdle
	ac.MaxSessionAge = cfg.SessionMaxAge
	ac.PasswordResetTTL = cfg.PasswordResetTTL
	ac.PublicURL = cfg.PublicURL.String()
	ac.Issuer = "EasyRMM (" + cfg.PublicURL.Hostname() + ")"
	authSvc := auth.NewService(db, auditLog, hasher, sealer, mail, ac)
	sessions, err := httpapi.NewSessions(authSvc, cfg.SecretKeys[0].Raw, cfg.PublicURL.String(), !cfg.DevInsecureCookie)
	if err != nil {
		return nil, err
	}
	usersSvc := users.New(db, auditLog, authSvc, hasher)
	setup, err := usersapi.NewSetup(ctx, usersSvc, cfg.DataDir, log)
	if err != nil {
		return nil, err
	}
	d := &Deps{
		DB: db, Audit: auditLog, Auth: authSvc, Sessions: sessions,
		Tenancy: tenancy.New(db, auditLog), Users: usersSvc, Setup: setup,
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
	d.Agents = agents.New(db, auditLog, mesh, log)
	builds, err := agents.LoadBuilds(cfg.AgentDir)
	if err != nil {
		return nil, err
	}
	if len(builds.List()) == 0 {
		log.Warn("no EasyRMM agent builds found; the console cannot offer agent downloads", "dir", cfg.AgentDir)
	}
	d.AgentBuilds = builds
	return d, nil
}

// buildRemote assembles the MeshCentral integration.
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
	svc = remote.New(d.DB, d.Audit, client, remote.Config{MeshURL: cfg.MeshPublicURL, LoginKey: sec.LoginKey}, log)
	gw, err := remote.NewGateway(svc, remote.GatewayConfig{Upstream: cfg.Mesh.InternalURL, Secure: !cfg.DevInsecureCookie}, log)
	if err != nil {
		return err
	}
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
	return meshcentral.ServerConfig{
		Hostname:      cfg.MeshPublicURL.Hostname(),
		Listen:        cfg.Mesh.InternalURL.Host,
		PublicPort:    port,
		TrustedProxy:  cfg.Mesh.InternalURL.Hostname(),
		FramingOrigin: cfg.PublicURL.Scheme + "://" + cfg.PublicURL.Host,
		CertURL:       cfg.Mesh.CertURL,
		LoginKey:      sec.LoginKey,
		SessionKey:    sec.SessionKey,
	}
}

// writeMeshConfig writes MeshCentral's config.json. MeshCentral's start
// script restarts it when the file changes.
func writeMeshConfig(cfg *config.Config, sec *remote.Secrets, log *slog.Logger) error {
	content, err := MeshServerConfig(cfg, sec).Render()
	if err != nil {
		return err
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

// Handler builds the complete HTTP handler for the application origin.
func Handler(cfg *config.Config, d *Deps, log *slog.Logger) (http.Handler, error) {
	mux := http.NewServeMux()
	authapi.New(d.Auth, d.Sessions, authapi.Features{RemoteAccess: d.Remote != nil}).Register(mux)
	tenancyapi.New(d.Tenancy).Register(mux)
	devicesapi.New(d.Devices).Register(mux)
	enrollapi.New(d.Agents, d.AgentBuilds, cfg.PublicURL.String()).Register(mux)
	if d.Remote != nil {
		remoteapi.New(d.Remote).Register(mux)
	}
	usersapi.New(d.Users, d.Setup).Register(mux)
	auditapi.New(d.Audit).Register(mux)
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
	mux.Handle("/", webui.Handler(files))

	trusted := cfg.TrustedProxies
	if cfg.TLSMode != config.TLSOffload {
		trusted = nil // nobody sits in front of us
	}
	frameOrigin := ""
	if cfg.MeshPublicURL != nil {
		frameOrigin = cfg.MeshPublicURL.String()
	}
	app := httpapi.Chain(mux,
		httpapi.SecurityHeaders(!cfg.DevInsecureCookie, frameOrigin),
		d.Sessions.Load,
		d.Sessions.CSRF,
	)
	agentAPI, err := agentapi.New(d.Agents, d.AgentBuilds, cfg.PublicURL.String(), log)
	if err != nil {
		return nil, err
	}
	// Agents carry no browser session: their routes skip the session and
	// CSRF layers and authenticate every request themselves.
	agentHandler := httpapi.Chain(agentAPI.Handler(), httpapi.SecurityHeaders(!cfg.DevInsecureCookie, ""))
	publicHost := strings.ToLower(cfg.PublicURL.Hostname())
	meshHost := ""
	if d.Gateway != nil {
		meshHost = strings.ToLower(cfg.MeshPublicURL.Hostname())
	}
	hosts := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.ToLower(strings.TrimSuffix(hostOnly(r.Host), ".")) {
		case publicHost:
			if strings.HasPrefix(r.URL.Path, agentproto.PathPrefix) {
				agentHandler.ServeHTTP(w, r)
				return
			}
			app.ServeHTTP(w, r)
		case meshHost:
			// Remote access: agents, and browsers holding a session grant.
			d.Gateway.ServeHTTP(w, r)
		default:
			httpapi.WriteError(w, r, &httpapi.Error{Status: http.StatusMisdirectedRequest, Code: "unknown_host", Message: "This server does not serve that hostname."})
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
	db, err := database.Open(ctx, cfg.DatabaseURL, database.PoolOptions{MaxConns: cfg.DatabaseMaxConns})
	if err != nil {
		return err
	}
	defer db.Close()

	var mail auth.Mailer
	if cfg.SMTP.Host != "" {
		m, err := mailer.New(mailer.Config{
			Host: cfg.SMTP.Host, Port: cfg.SMTP.Port, Username: cfg.SMTP.Username,
			Password: cfg.SMTP.Password, From: cfg.SMTP.From, TLS: cfg.SMTP.TLS,
		})
		if err != nil {
			return err
		}
		mail = m
	} else {
		log.Info("e-mail is not configured: self-service password reset is disabled and administrators deliver invitation links themselves")
	}

	deps, err := Build(ctx, cfg, db, mail, log)
	if err != nil {
		return err
	}
	h, err := Handler(cfg, deps, log)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
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
	tasks = append(tasks, deps.Agents.Cleanup)
	wg.Go(func() { maintain(ctx, db, cfg.AuditRetention, log, tasks...) })
	healthErr := make(chan error, 1)
	if cfg.ListenHealth != "" {
		wg.Go(func() { healthErr <- serveHealth(ctx, cfg.ListenHealth, db, log) })
	}
	e := &edge{cfg: cfg, handler: h, log: log}
	runErr := e.run(ctx)
	cancel()
	wg.Wait()
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
// /healthz (process is up) and /readyz (database reachable).
func serveHealth(ctx context.Context, addr string, db *database.DB, log *slog.Logger) error {
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
		_, _ = w.Write([]byte("ready\n"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
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
		_, err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE expires_at < now() - interval '1 day'`)
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
