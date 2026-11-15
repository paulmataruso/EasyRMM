package site

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/paulmataruso/easyrm/internal/audit"
	"github.com/paulmataruso/easyrm/internal/organization"
	"github.com/paulmataruso/easyrm/pkg/middleware"
	"github.com/paulmataruso/easyrm/pkg/models"
)

type Handler struct {
	store      *Store
	orgStore   *organization.Store
	auditStore *audit.Store
	logger     *slog.Logger
}

func NewHandler(store *Store, orgStore *organization.Store, auditStore *audit.Store, logger *slog.Logger) *Handler {
	return &Handler{store: store, orgStore: orgStore, auditStore: auditStore, logger: logger}
}

type createSiteRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization ID")
		return
	}

	var req createSiteRequest
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

	site, err := h.store.Create(r.Context(), orgID, req.Name, req.Slug, nil)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			middleware.Error(w, http.StatusConflict, "site slug already exists in this organization")
			return
		}
		h.logger.Error("failed to create site", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to create site")
		return
	}

	user := middleware.UserFromContext(r.Context())
	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:         &user.ID,
		OrganizationID: &orgID,
		Action:         "site.create",
		ResourceType:   "site",
		ResourceID:     site.ID.String(),
		IPAddress:      r.RemoteAddr,
	})

	middleware.JSON(w, http.StatusCreated, site)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(chi.URLParam(r, "orgID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization ID")
		return
	}

	sites, err := h.store.List(r.Context(), orgID)
	if err != nil {
		h.logger.Error("failed to list sites", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to list sites")
		return
	}

	middleware.JSON(w, http.StatusOK, sites)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid site ID")
		return
	}

	site, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		middleware.Error(w, http.StatusNotFound, "site not found")
		return
	}

	middleware.JSON(w, http.StatusOK, site)
}

type updateSiteRequest struct {
	Name     *string        `json:"name,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid site ID")
		return
	}

	var req updateSiteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	site, err := h.store.Update(r.Context(), id, UpdateParams{Name: req.Name, Settings: req.Settings})
	if err != nil {
		h.logger.Error("failed to update site", "error", err, "id", id)
		middleware.Error(w, http.StatusInternalServerError, "failed to update site")
		return
	}

	user := middleware.UserFromContext(r.Context())
	orgID, _ := uuid.Parse(chi.URLParam(r, "orgID"))
	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:         &user.ID,
		OrganizationID: &orgID,
		Action:         "site.update",
		ResourceType:   "site",
		ResourceID:     site.ID.String(),
		IPAddress:      r.RemoteAddr,
	})

	middleware.JSON(w, http.StatusOK, site)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid site ID")
		return
	}

	if err := h.store.Delete(r.Context(), id); err != nil {
		h.logger.Error("failed to delete site", "error", err, "id", id)
		middleware.Error(w, http.StatusInternalServerError, "failed to delete site")
		return
	}

	user := middleware.UserFromContext(r.Context())
	orgID, _ := uuid.Parse(chi.URLParam(r, "orgID"))
	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:         &user.ID,
		OrganizationID: &orgID,
		Action:         "site.delete",
		ResourceType:   "site",
		ResourceID:     id.String(),
		IPAddress:      r.RemoteAddr,
	})

	w.WriteHeader(http.StatusNoContent)
}
