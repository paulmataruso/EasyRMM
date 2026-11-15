package alerting

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/paulmataruso/easyrm/internal/audit"
	"github.com/paulmataruso/easyrm/internal/auth"
	"github.com/paulmataruso/easyrm/pkg/middleware"
	"github.com/paulmataruso/easyrm/pkg/models"
)

type Handler struct {
	store      *Store
	auditStore *audit.Store
	logger     *slog.Logger
}

func NewHandler(store *Store, auditStore *audit.Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, auditStore: auditStore, logger: logger}
}

// ── Rules ─────────────────────────────────────────────────────

func (h *Handler) CreateRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrganizationID string         `json:"organization_id"`
		Name           string         `json:"name"`
		Description    string         `json:"description"`
		Metric         string         `json:"metric"`
		Condition      map[string]any `json:"condition"`
		Severity       string         `json:"severity"`
		Enabled        *bool          `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" || body.Metric == "" {
		middleware.Error(w, http.StatusBadRequest, "name and metric are required")
		return
	}

	var orgID *uuid.UUID
	if body.OrganizationID != "" {
		id, err := uuid.Parse(body.OrganizationID)
		if err != nil {
			middleware.Error(w, http.StatusBadRequest, "invalid organization_id")
			return
		}
		orgID = &id
	}

	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	if body.Severity == "" {
		body.Severity = "warning"
	}

	rule, err := h.store.CreateRule(r.Context(), CreateRuleParams{
		OrganizationID: orgID,
		Name:           body.Name,
		Description:    body.Description,
		Metric:         body.Metric,
		Condition:      body.Condition,
		Severity:       body.Severity,
		Enabled:        enabled,
	})
	if err != nil {
		h.logger.Error("failed to create alert rule", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to create alert rule")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user != nil {
		h.auditStore.Log(r.Context(), models.AuditLog{
			UserID:       &user.ID,
			Action:       "alert_rule.create",
			ResourceType: "alert_rule",
			ResourceID:   rule.ID.String(),
		})
	}

	middleware.JSON(w, http.StatusCreated, rule)
}

func (h *Handler) ListRules(w http.ResponseWriter, r *http.Request) {
	orgIDStr := r.URL.Query().Get("organization_id")
	if orgIDStr == "" {
		orgIDStr = r.URL.Query().Get("org_id")
	}
	if orgIDStr == "" {
		middleware.Error(w, http.StatusBadRequest, "organization_id is required")
		return
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization_id")
		return
	}

	rules, err := h.store.ListRules(r.Context(), orgID)
	if err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to list alert rules")
		return
	}

	middleware.JSON(w, http.StatusOK, map[string]any{"rules": rules})
}

func (h *Handler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	var body struct {
		Name        *string        `json:"name"`
		Description *string        `json:"description"`
		Metric      *string        `json:"metric"`
		Condition   map[string]any `json:"condition"`
		Severity    *string        `json:"severity"`
		IsActive    *bool          `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	rule, err := h.store.UpdateRule(r.Context(), id, UpdateRuleParams{
		Name:        body.Name,
		Description: body.Description,
		Metric:      body.Metric,
		Condition:   body.Condition,
		Severity:    body.Severity,
		IsActive:    body.IsActive,
	})
	if err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to update alert rule")
		return
	}

	middleware.JSON(w, http.StatusOK, rule)
}

func (h *Handler) DeleteRule(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "ruleID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid rule ID")
		return
	}

	if err := h.store.DeleteRule(r.Context(), id); err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to delete alert rule")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user != nil {
		h.auditStore.Log(r.Context(), models.AuditLog{
			UserID:       &user.ID,
			Action:       "alert_rule.delete",
			ResourceType: "alert_rule",
			ResourceID:   id.String(),
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── Alerts ────────────────────────────────────────────────────

func (h *Handler) ListAlerts(w http.ResponseWriter, r *http.Request) {
	orgIDStr := r.URL.Query().Get("organization_id")
	if orgIDStr == "" {
		orgIDStr = r.URL.Query().Get("org_id")
	}
	if orgIDStr == "" {
		middleware.Error(w, http.StatusBadRequest, "organization_id is required")
		return
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization_id")
		return
	}

	var deviceID *uuid.UUID
	if d := r.URL.Query().Get("device_id"); d != "" {
		id, err := uuid.Parse(d)
		if err != nil {
			middleware.Error(w, http.StatusBadRequest, "invalid device_id")
			return
		}
		deviceID = &id
	}

	alerts, total, err := h.store.ListAlerts(r.Context(), orgID, AlertListFilters{
		Status:   r.URL.Query().Get("status"),
		Severity: r.URL.Query().Get("severity"),
		DeviceID: deviceID,
	})
	if err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to list alerts")
		return
	}

	middleware.JSON(w, http.StatusOK, map[string]any{"alerts": alerts, "total": total})
}

func (h *Handler) AcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	alertID, err := uuid.Parse(chi.URLParam(r, "alertID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid alert ID")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		middleware.Error(w, http.StatusUnauthorized, "authentication required")
		return
	}

	alert, err := h.store.AcknowledgeAlert(r.Context(), alertID, user.ID)
	if err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to acknowledge alert")
		return
	}

	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:       &user.ID,
		Action:       "alert.acknowledge",
		ResourceType: "alert",
		ResourceID:   alertID.String(),
	})

	middleware.JSON(w, http.StatusOK, alert)
}

func (h *Handler) ResolveAlert(w http.ResponseWriter, r *http.Request) {
	alertID, err := uuid.Parse(chi.URLParam(r, "alertID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid alert ID")
		return
	}

	alert, err := h.store.ResolveAlert(r.Context(), alertID)
	if err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to resolve alert")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user != nil {
		h.auditStore.Log(r.Context(), models.AuditLog{
			UserID:       &user.ID,
			Action:       "alert.resolve",
			ResourceType: "alert",
			ResourceID:   alertID.String(),
		})
	}

	middleware.JSON(w, http.StatusOK, alert)
}
