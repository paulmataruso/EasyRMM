package enrollment

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/paulmataruso/easyrm/internal/audit"
	"github.com/paulmataruso/easyrm/internal/config"
	"github.com/paulmataruso/easyrm/internal/device"
	"github.com/paulmataruso/easyrm/pkg/middleware"
	"github.com/paulmataruso/easyrm/pkg/models"
)

type Handler struct {
	store       *Store
	deviceStore *device.Store
	auditStore  *audit.Store
	cfg         *config.Config
	logger      *slog.Logger
}

func NewHandler(store *Store, deviceStore *device.Store, auditStore *audit.Store, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		store:       store,
		deviceStore: deviceStore,
		auditStore:  auditStore,
		cfg:         cfg,
		logger:      logger,
	}
}

type enrollRequest struct {
	Token          string `json:"token"`
	Hostname       string `json:"hostname"`
	OSType         string `json:"os_type"`
	OSName         string `json:"os_name"`
	OSVersion      string `json:"os_version"`
	Arch           string `json:"arch"`
	MeshNodeID     string `json:"mesh_node_id"`
	CPUModel       string `json:"cpu_model"`
	CPUCores       int    `json:"cpu_cores"`
	TotalMemoryMB  int64  `json:"total_memory_mb"`
	SerialNumber   string `json:"serial_number"`
	Manufacturer   string `json:"manufacturer"`
	Model          string `json:"model"`
}

type enrollResponse struct {
	DeviceID  uuid.UUID `json:"device_id"`
	AgentID   string    `json:"agent_id"`
	ServerURL string    `json:"server_url"`
}

func (h *Handler) Enroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Token == "" || req.Hostname == "" || req.OSType == "" {
		middleware.Error(w, http.StatusBadRequest, "token, hostname, and os_type are required")
		return
	}

	if req.OSType != "windows" && req.OSType != "linux" {
		middleware.Error(w, http.StatusBadRequest, "os_type must be 'windows' or 'linux'")
		return
	}

	tokenHash := middleware.HashToken(req.Token)
	token, err := h.store.ValidateToken(r.Context(), tokenHash)
	if err != nil {
		h.logger.Warn("invalid enrollment token", "error", err, "ip", r.RemoteAddr)
		middleware.Error(w, http.StatusUnauthorized, "invalid or expired enrollment token")
		return
	}

	agentID, err := generateAgentID()
	if err != nil {
		h.logger.Error("failed to generate agent ID", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	created, err := h.deviceStore.Create(r.Context(), device.CreateParams{
		OrganizationID: token.OrganizationID,
		SiteID:         *token.SiteID,
		DeviceGroupID:  token.DeviceGroupID,
		Hostname:       req.Hostname,
		OSType:         req.OSType,
		AgentID:        agentID,
		MeshNodeID:     req.MeshNodeID,
	})
	if err != nil {
		h.logger.Error("failed to create device", "error", err, "hostname", req.Hostname)
		middleware.Error(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	if err := h.store.IncrementTokenUse(r.Context(), token.ID); err != nil {
		h.logger.Error("failed to increment token use count", "error", err)
	}

	h.auditStore.Log(r.Context(), models.AuditLog{
		OrganizationID: &token.OrganizationID,
		DeviceID:       &created.ID,
		Action:         "device.enroll",
		ResourceType:   "device",
		ResourceID:     created.ID.String(),
		Details:        map[string]any{"hostname": req.Hostname, "os_type": req.OSType, "agent_id": agentID},
		IPAddress:      r.RemoteAddr,
	})

	middleware.JSON(w, http.StatusCreated, enrollResponse{
		DeviceID:  created.ID,
		AgentID:   agentID,
		ServerURL: h.cfg.Server.PublicURL,
	})
}

type checkInRequest struct {
	AgentID       string   `json:"agent_id"`
	CPUPercent    *float64 `json:"cpu_percent,omitempty"`
	MemoryPercent *float64 `json:"memory_percent,omitempty"`
	AgentVersion  string   `json:"agent_version,omitempty"`
}

func (h *Handler) CheckIn(w http.ResponseWriter, r *http.Request) {
	var req checkInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.AgentID == "" {
		middleware.Error(w, http.StatusBadRequest, "agent_id is required")
		return
	}

	dev, err := h.deviceStore.GetByAgentID(r.Context(), req.AgentID)
	if err != nil {
		middleware.Error(w, http.StatusUnauthorized, "unknown agent")
		return
	}

	if err := h.deviceStore.UpdateLastSeen(r.Context(), dev.ID); err != nil {
		h.logger.Error("failed to update last seen", "error", err, "device_id", dev.ID)
	}

	// Return pending jobs for this device
	middleware.JSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"pending_jobs": []any{},
	})
}

type createTokenRequest struct {
	Name           string     `json:"name"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	SiteID         *uuid.UUID `json:"site_id"`
	DeviceGroupID  *uuid.UUID `json:"device_group_id"`
	MaxUses        *int       `json:"max_uses"`
	ExpiresInHours *int       `json:"expires_in_hours"`
}

type createTokenResponse struct {
	Token string              `json:"token"`
	Info  models.EnrollmentToken `json:"info"`
}

func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.OrganizationID == uuid.Nil {
		middleware.Error(w, http.StatusBadRequest, "organization_id is required")
		return
	}

	token, err := generateToken()
	if err != nil {
		h.logger.Error("failed to generate enrollment token", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	tokenHash := middleware.HashToken(token)
	user := middleware.UserFromContext(r.Context())

	var expiresAt *time.Time
	if req.ExpiresInHours != nil {
		t := time.Now().Add(time.Duration(*req.ExpiresInHours) * time.Hour)
		expiresAt = &t
	}

	et := models.EnrollmentToken{
		OrganizationID: req.OrganizationID,
		SiteID:         req.SiteID,
		DeviceGroupID:  req.DeviceGroupID,
		TokenHash:      tokenHash,
		Name:           req.Name,
		MaxUses:        req.MaxUses,
		ExpiresAt:      expiresAt,
		CreatedBy:      user.ID,
	}

	created, err := h.store.Create(r.Context(), et)
	if err != nil {
		h.logger.Error("failed to create enrollment token", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:         &user.ID,
		OrganizationID: &req.OrganizationID,
		Action:         "enrollment_token.create",
		ResourceType:   "enrollment_token",
		ResourceID:     created.ID.String(),
		IPAddress:      r.RemoteAddr,
	})

	middleware.JSON(w, http.StatusCreated, createTokenResponse{
		Token: token,
		Info:  *created,
	})
}

func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	orgIDStr := r.URL.Query().Get("org_id")
	if orgIDStr == "" {
		middleware.Error(w, http.StatusBadRequest, "org_id query parameter is required")
		return
	}

	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization ID")
		return
	}

	tokens, err := h.store.List(r.Context(), orgID)
	if err != nil {
		h.logger.Error("failed to list enrollment tokens", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}

	middleware.JSON(w, http.StatusOK, tokens)
}

func (h *Handler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "tokenID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid token ID")
		return
	}

	if err := h.store.Revoke(r.Context(), id); err != nil {
		h.logger.Error("failed to revoke enrollment token", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to revoke token")
		return
	}

	user := middleware.UserFromContext(r.Context())
	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:       &user.ID,
		Action:       "enrollment_token.revoke",
		ResourceType: "enrollment_token",
		ResourceID:   id.String(),
		IPAddress:    r.RemoteAddr,
	})

	w.WriteHeader(http.StatusNoContent)
}

func generateAgentID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "agent-" + hex.EncodeToString(b), nil
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
