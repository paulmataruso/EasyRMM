package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/paulmataruso/easyrm/internal/agent"
	"github.com/paulmataruso/easyrm/internal/alerting"
	"github.com/paulmataruso/easyrm/internal/auth"
	"github.com/paulmataruso/easyrm/internal/audit"
	"github.com/paulmataruso/easyrm/internal/config"
	"github.com/paulmataruso/easyrm/internal/device"
	"github.com/paulmataruso/easyrm/internal/enrollment"
	"github.com/paulmataruso/easyrm/internal/job"
	"github.com/paulmataruso/easyrm/internal/meshcentral"
	"github.com/paulmataruso/easyrm/internal/organization"
	"github.com/paulmataruso/easyrm/internal/script"
	"github.com/paulmataruso/easyrm/internal/site"
	"github.com/paulmataruso/easyrm/pkg/middleware"
)

type Server struct {
	cfg    *config.Config
	pool   *pgxpool.Pool
	router *chi.Mux
	http   *http.Server
	logger *slog.Logger
}

func New(cfg *config.Config, pool *pgxpool.Pool, logger *slog.Logger) *Server {
	s := &Server{
		cfg:    cfg,
		pool:   pool,
		logger: logger,
	}
	s.setupRouter()
	return s
}

func (s *Server) setupRouter() {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(middleware.Logger(s.logger))
	r.Use(chimw.Recoverer)
	r.Use(chimw.Compress(5))
	r.Use(middleware.SecureHeaders)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{s.cfg.Server.PublicURL},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-XSRF-TOKEN"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Initialize stores
	auditStore := audit.NewStore(s.pool)
	authStore := auth.NewStore(s.pool, s.cfg.Auth)
	orgStore := organization.NewStore(s.pool)
	siteStore := site.NewStore(s.pool)
	deviceStore := device.NewStore(s.pool)
	enrollmentStore := enrollment.NewStore(s.pool)
	scriptStore := script.NewStore(s.pool)
	jobStore := job.NewStore(s.pool)
	alertStore := alerting.NewStore(s.pool)

	// Initialize agent hub and handlers
	agentHub := agent.NewHub(s.logger)
	meshClient := meshcentral.NewClient(s.cfg.MeshCentral)
	authHandler := auth.NewHandler(authStore, s.cfg.Auth)
	orgHandler := organization.NewHandler(orgStore, auditStore, s.logger)
	siteHandler := site.NewHandler(siteStore, orgStore, auditStore, s.logger)
	deviceHandler := device.NewHandler(deviceStore, auditStore, s.logger)
	enrollmentHandler := enrollment.NewHandler(enrollmentStore, deviceStore, auditStore, s.cfg, s.logger)
	agentHandler := agent.NewHandler(agentHub, deviceStore, s.logger)
	meshHandler := meshcentral.NewHandler(meshClient, deviceStore, s.logger)
	scriptHandler := script.NewHandler(scriptStore, auditStore, s.logger)
	jobHandler := job.NewHandler(jobStore, auditStore, s.logger)
	alertHandler := alerting.NewHandler(alertStore, auditStore, s.logger)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public auth routes (rate limited)
		r.Group(func(r chi.Router) {
			r.Use(middleware.RateLimit(s.cfg.Auth.RateLimitPerMin))
			r.Post("/auth/login", authHandler.Login)
		})

		// Agent endpoints (agent-authenticated, not user-authenticated)
		r.Group(func(r chi.Router) {
			r.Post("/agent/enroll", enrollmentHandler.Enroll)
			r.Post("/agent/checkin", enrollmentHandler.CheckIn)
		})

		// Authenticated routes
		r.Group(func(r chi.Router) {
			r.Use(RequireAuth(authStore))

			// Auth
			r.Post("/auth/logout", authHandler.Logout)
			r.Get("/auth/me", authHandler.Me)
			r.Put("/auth/password", authHandler.ChangePassword)
			r.Post("/auth/mfa/setup", authHandler.MFASetup)
			r.Post("/auth/mfa/verify", authHandler.MFAVerify)
			r.Post("/auth/mfa/disable", authHandler.MFADisable)

			// Users (super admin only)
			r.Route("/users", func(r chi.Router) {
				r.Use(RequireRole("super_admin"))
				r.Get("/", listUsersHandler(authStore))
				r.Post("/", createUserHandler(authStore, auditStore))
			})

			// Organizations
			r.Route("/organizations", func(r chi.Router) {
				r.Get("/", orgHandler.List)
				r.Group(func(r chi.Router) {
					r.Use(RequireRole("super_admin"))
					r.Post("/", orgHandler.Create)
				})
				r.Route("/{orgID}", func(r chi.Router) {
					r.Use(RequireOrgAccess(authStore))
					r.Get("/", orgHandler.Get)
					r.Put("/", orgHandler.Update)
					r.Delete("/", orgHandler.Delete)

					// Sites within organization
					r.Route("/sites", func(r chi.Router) {
						r.Get("/", siteHandler.List)
						r.Post("/", siteHandler.Create)
						r.Route("/{siteID}", func(r chi.Router) {
							r.Get("/", siteHandler.Get)
							r.Put("/", siteHandler.Update)
							r.Delete("/", siteHandler.Delete)
						})
					})
				})
			})

			// Devices
			r.Route("/devices", func(r chi.Router) {
				r.Get("/", deviceHandler.List)
				r.Get("/stats", deviceHandler.Stats)
				r.Route("/{deviceID}", func(r chi.Router) {
					r.Get("/", deviceHandler.Get)
					r.Put("/", deviceHandler.Update)
					r.Delete("/", deviceHandler.Delete)
					r.Get("/remote-access", meshHandler.GetRemoteAccessToken)
				})
			})

			// MeshCentral
			r.Get("/mesh/config", meshHandler.GetMeshConfig)

			// Enrollment tokens
			r.Route("/enrollment-tokens", func(r chi.Router) {
				r.Get("/", enrollmentHandler.ListTokens)
				r.Post("/", enrollmentHandler.CreateToken)
				r.Delete("/{tokenID}", enrollmentHandler.RevokeToken)
			})

			// Scripts
			r.Route("/scripts", func(r chi.Router) {
				r.Get("/", scriptHandler.List)
				r.Post("/", scriptHandler.Create)
				r.Route("/{scriptID}", func(r chi.Router) {
					r.Get("/", scriptHandler.Get)
					r.Put("/", scriptHandler.Update)
					r.Delete("/", scriptHandler.Delete)
				})
			})

			// Jobs
			r.Route("/jobs", func(r chi.Router) {
				r.Get("/", jobHandler.List)
				r.Post("/", jobHandler.Create)
				r.Route("/{jobID}", func(r chi.Router) {
					r.Get("/", jobHandler.Get)
					r.Get("/results", jobHandler.GetResults)
				})
			})

			// Alerts
			r.Route("/alerts", func(r chi.Router) {
				r.Get("/", alertHandler.ListAlerts)
				r.Route("/{alertID}", func(r chi.Router) {
					r.Post("/acknowledge", alertHandler.AcknowledgeAlert)
					r.Post("/resolve", alertHandler.ResolveAlert)
				})
			})

			// Alert rules
			r.Route("/alert-rules", func(r chi.Router) {
				r.Get("/", alertHandler.ListRules)
				r.Post("/", alertHandler.CreateRule)
				r.Route("/{ruleID}", func(r chi.Router) {
					r.Put("/", alertHandler.UpdateRule)
					r.Delete("/", alertHandler.DeleteRule)
				})
			})

			// Dashboard
			r.Get("/dashboard/stats", dashboardHandler(deviceStore, auditStore))

			// Audit logs
			r.Get("/audit-logs", auditLogsHandler(auditStore))
		})
	})

	// WebSocket endpoint for agents
	r.Get("/ws/agent", agentHandler.HandleWebSocket)

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		if err := s.pool.Ping(r.Context()); err != nil {
			middleware.JSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unhealthy"})
			return
		}
		middleware.JSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	})

	// Serve frontend SPA (catch-all)
	r.Get("/*", s.serveSPA)

	s.router = r
}

// Re-export middleware auth functions using the concrete auth.Store type
func RequireAuth(store *auth.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("__Host-session")
			if err != nil || cookie.Value == "" {
				middleware.Error(w, http.StatusUnauthorized, "authentication required")
				return
			}

			tokenHash := auth.HashToken(cookie.Value)
			sess, err := store.GetSessionByToken(r.Context(), tokenHash)
			if err != nil {
				middleware.Error(w, http.StatusUnauthorized, "session expired or invalid")
				return
			}

			user, err := store.GetUserByID(r.Context(), sess.UserID)
			if err != nil {
				middleware.Error(w, http.StatusInternalServerError, "internal error")
				return
			}

			if !user.IsActive {
				middleware.Error(w, http.StatusForbidden, "account is disabled")
				return
			}

			ctx := auth.SetUserContext(r.Context(), user)
			ctx = auth.SetSessionContext(ctx, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, role := range roles {
		allowed[role] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.UserFromContext(r.Context())
			if user == nil {
				middleware.Error(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if user.Role == "super_admin" {
				next.ServeHTTP(w, r)
				return
			}
			if !allowed[user.Role] {
				middleware.Error(w, http.StatusForbidden, "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func RequireOrgAccess(store *auth.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := auth.UserFromContext(r.Context())
			if user == nil {
				middleware.Error(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if user.Role == "super_admin" {
				next.ServeHTTP(w, r)
				return
			}
			orgID := chi.URLParam(r, "orgID")
			if orgID == "" {
				middleware.Error(w, http.StatusBadRequest, "organization ID required")
				return
			}
			orgs, err := store.GetUserOrganizations(r.Context(), user.ID)
			if err != nil {
				middleware.Error(w, http.StatusInternalServerError, "internal error")
				return
			}
			for _, a := range orgs {
				if a.OrganizationID.String() == orgID {
					next.ServeHTTP(w, r)
					return
				}
			}
			middleware.Error(w, http.StatusForbidden, "no access to this organization")
		})
	}
}

func listUsersHandler(store *auth.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := store.ListUsers(r.Context())
		if err != nil {
			middleware.Error(w, http.StatusInternalServerError, "failed to list users")
			return
		}
		middleware.JSON(w, http.StatusOK, users)
	}
}

func createUserHandler(store *auth.Store, auditStore *audit.Store) http.HandlerFunc {
	type req struct {
		Email       string `json:"email"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		var body req
		if err := decodeJSON(r, &body); err != nil {
			middleware.Error(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if body.Email == "" || body.Username == "" || body.Password == "" {
			middleware.Error(w, http.StatusBadRequest, "email, username, and password are required")
			return
		}
		user, err := store.CreateUser(r.Context(), body.Email, body.Username, body.Password, body.DisplayName, body.Role)
		if err != nil {
			middleware.Error(w, http.StatusInternalServerError, "failed to create user")
			return
		}
		middleware.JSON(w, http.StatusCreated, user)
	}
}

func dashboardHandler(deviceStore *device.Store, auditStore *audit.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := deviceStore.CountByStatus(r.Context(), nil)
		if err != nil {
			middleware.Error(w, http.StatusInternalServerError, "failed to get stats")
			return
		}
		middleware.JSON(w, http.StatusOK, stats)
	}
}

func auditLogsHandler(auditStore *audit.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.UserFromContext(r.Context())
		if user == nil {
			middleware.Error(w, http.StatusUnauthorized, "authentication required")
			return
		}

		// For now, return empty for non-super-admins without an org filter
		orgIDStr := r.URL.Query().Get("org_id")
		if orgIDStr == "" && user.Role != "super_admin" {
			middleware.Error(w, http.StatusBadRequest, "org_id is required")
			return
		}

		var orgID uuid.UUID
		if orgIDStr != "" {
			var err error
			orgID, err = uuid.Parse(orgIDStr)
			if err != nil {
				middleware.Error(w, http.StatusBadRequest, "invalid org_id")
				return
			}
		}

		logs, total, err := auditStore.List(r.Context(), orgID, audit.ListFilters{Limit: 50})
		if err != nil {
			middleware.Error(w, http.StatusInternalServerError, "failed to list audit logs")
			return
		}
		middleware.JSON(w, http.StatusOK, map[string]any{"logs": logs, "total": total})
	}
}

func (s *Server) serveSPA(w http.ResponseWriter, r *http.Request) {
	staticDir := http.Dir("./frontend/dist")
	if f, err := staticDir.Open(r.URL.Path); err == nil {
		f.Close()
		http.FileServer(staticDir).ServeHTTP(w, r)
		return
	}
	http.ServeFile(w, r, "./frontend/dist/index.html")
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)
	s.http = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  s.cfg.Server.ReadTimeout,
		WriteTimeout: s.cfg.Server.WriteTimeout,
		IdleTimeout:  120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("server starting", "addr", addr)
		if s.cfg.Server.TLSCert != "" && s.cfg.Server.TLSKey != "" {
			errCh <- s.http.ListenAndServeTLS(s.cfg.Server.TLSCert, s.cfg.Server.TLSKey)
		} else {
			errCh <- s.http.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	case sig := <-stop:
		s.logger.Info("shutdown signal received", "signal", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := s.http.Shutdown(ctx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	s.logger.Info("server stopped")
	return nil
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
