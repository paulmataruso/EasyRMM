package organization

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/paulmataruso/easyrm/internal/audit"
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

type createOrgRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req createOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(strings.ToLower(req.Slug))

	if req.Name == "" {
		middleware.Error(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Slug == "" {
		middleware.Error(w, http.StatusBadRequest, "slug is required")
		return
	}

	org, err := h.store.Create(r.Context(), req.Name, req.Slug, nil)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			middleware.Error(w, http.StatusConflict, "organization slug already exists")
			return
		}
		h.logger.Error("failed to create organization", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to create organization")
		return
	}

	user := middleware.UserFromContext(r.Context())
	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:         &user.ID,
		OrganizationID: &org.ID,
		Action:         "organization.create",
		ResourceType:   "organization",
		ResourceID:     org.ID.String(),
		IPAddress:      r.RemoteAddr,
	})

	middleware.JSON(w, http.StatusCreated, org)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	user := middleware.UserFromContext(r.Context())

	var orgs []models.Organization
	var err error

	if user.Role == models.RoleSuperAdmin {
		orgs, err = h.store.List(r.Context())
	} else {
		orgs, err = h.store.ListForUser(r.Context(), user.ID)
	}

	if err != nil {
		h.logger.Error("failed to list organizations", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to list organizations")
		return
	}

	middleware.JSON(w, http.StatusOK, orgs)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization ID")
		return
	}

	org, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		middleware.Error(w, http.StatusNotFound, "organization not found")
		return
	}

	middleware.JSON(w, http.StatusOK, org)
}

type updateOrgRequest struct {
	Name     *string        `json:"name,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization ID")
		return
	}

	var req updateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	org, err := h.store.Update(r.Context(), id, UpdateParams{Name: req.Name, Settings: req.Settings})
	if err != nil {
		h.logger.Error("failed to update organization", "error", err, "id", id)
		middleware.Error(w, http.StatusInternalServerError, "failed to update organization")
		return
	}

	user := middleware.UserFromContext(r.Context())
	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:         &user.ID,
		OrganizationID: &org.ID,
		Action:         "organization.update",
		ResourceType:   "organization",
		ResourceID:     org.ID.String(),
		IPAddress:      r.RemoteAddr,
	})

	middleware.JSON(w, http.StatusOK, org)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization ID")
		return
	}

	if err := h.store.Delete(r.Context(), id); err != nil {
		h.logger.Error("failed to delete organization", "error", err, "id", id)
		middleware.Error(w, http.StatusInternalServerError, "failed to delete organization")
		return
	}

	user := middleware.UserFromContext(r.Context())
	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:       &user.ID,
		Action:       "organization.delete",
		ResourceType: "organization",
		ResourceID:   id.String(),
		IPAddress:    r.RemoteAddr,
	})

	w.WriteHeader(http.StatusNoContent)
}
