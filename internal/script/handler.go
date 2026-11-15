package script

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

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrganizationID string `json:"organization_id"`
		Name           string `json:"name"`
		Description    string `json:"description"`
		Shell          string `json:"shell"`
		OSType         string `json:"os_type"`
		Content        string `json:"content"`
		TimeoutSeconds int    `json:"timeout_seconds"`
		Category       string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Name == "" || body.Content == "" {
		middleware.Error(w, http.StatusBadRequest, "name and content are required")
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

	user := auth.UserFromContext(r.Context())
	var createdBy *uuid.UUID
	if user != nil {
		createdBy = &user.ID
	}

	sc, err := h.store.Create(r.Context(), CreateParams{
		OrganizationID: orgID,
		Name:           body.Name,
		Description:    body.Description,
		Shell:          body.Shell,
		OSType:         body.OSType,
		Content:        body.Content,
		TimeoutSeconds: body.TimeoutSeconds,
		Category:       body.Category,
		CreatedBy:      createdBy,
	})
	if err != nil {
		h.logger.Error("failed to create script", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to create script")
		return
	}

	if user != nil {
		h.auditStore.Log(r.Context(), models.AuditLog{
			UserID:       &user.ID,
			Action:       "script.create",
			ResourceType: "script",
			ResourceID:   sc.ID.String(),
		})
	}

	middleware.JSON(w, http.StatusCreated, sc)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	orgIDStr := r.URL.Query().Get("organization_id")
	if orgIDStr == "" {
		middleware.Error(w, http.StatusBadRequest, "organization_id is required")
		return
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization_id")
		return
	}

	scripts, err := h.store.List(r.Context(), orgID)
	if err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to list scripts")
		return
	}

	middleware.JSON(w, http.StatusOK, map[string]any{"scripts": scripts})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "scriptID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid script ID")
		return
	}

	sc, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		middleware.Error(w, http.StatusNotFound, "script not found")
		return
	}

	middleware.JSON(w, http.StatusOK, sc)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "scriptID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid script ID")
		return
	}

	var body struct {
		Name           *string `json:"name"`
		Description    *string `json:"description"`
		Content        *string `json:"content"`
		Shell          *string `json:"shell"`
		Category       *string `json:"category"`
		TimeoutSeconds *int    `json:"timeout_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	sc, err := h.store.Update(r.Context(), id, UpdateParams{
		Name:           body.Name,
		Description:    body.Description,
		Content:        body.Content,
		Shell:          body.Shell,
		Category:       body.Category,
		TimeoutSeconds: body.TimeoutSeconds,
	})
	if err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to update script")
		return
	}

	middleware.JSON(w, http.StatusOK, sc)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "scriptID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid script ID")
		return
	}

	if err := h.store.Delete(r.Context(), id); err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to delete script")
		return
	}

	user := auth.UserFromContext(r.Context())
	if user != nil {
		h.auditStore.Log(r.Context(), models.AuditLog{
			UserID:       &user.ID,
			Action:       "script.delete",
			ResourceType: "script",
			ResourceID:   id.String(),
		})
	}

	w.WriteHeader(http.StatusNoContent)
}
