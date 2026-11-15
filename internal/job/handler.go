package job

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

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
		OrganizationID string         `json:"organization_id"`
		Name           string         `json:"name"`
		JobType        string         `json:"job_type"`
		ScriptID       string         `json:"script_id"`
		TargetType     string         `json:"target_type"`
		TargetID       string         `json:"target_id"`
		Payload        map[string]any `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if body.Name == "" || body.JobType == "" || body.TargetType == "" || body.TargetID == "" {
		middleware.Error(w, http.StatusBadRequest, "name, job_type, target_type, and target_id are required")
		return
	}

	orgID, err := uuid.Parse(body.OrganizationID)
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid organization_id")
		return
	}

	targetID, err := uuid.Parse(body.TargetID)
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid target_id")
		return
	}

	var scriptID *uuid.UUID
	if body.ScriptID != "" {
		id, err := uuid.Parse(body.ScriptID)
		if err != nil {
			middleware.Error(w, http.StatusBadRequest, "invalid script_id")
			return
		}
		scriptID = &id
	}

	user := auth.UserFromContext(r.Context())
	if user == nil {
		middleware.Error(w, http.StatusUnauthorized, "authentication required")
		return
	}

	j, err := h.store.Create(r.Context(), CreateParams{
		OrganizationID: orgID,
		Name:           body.Name,
		JobType:        body.JobType,
		ScriptID:       scriptID,
		TargetType:     body.TargetType,
		TargetID:       targetID,
		CreatedBy:      user.ID,
		Payload:        body.Payload,
	})
	if err != nil {
		h.logger.Error("failed to create job", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to create job")
		return
	}

	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:       &user.ID,
		Action:       "job.create",
		ResourceType: "job",
		ResourceID:   j.ID.String(),
	})

	middleware.JSON(w, http.StatusCreated, j)
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

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	jobs, total, err := h.store.List(r.Context(), orgID, ListFilters{
		Status: r.URL.Query().Get("status"),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to list jobs")
		return
	}

	middleware.JSON(w, http.StatusOK, map[string]any{"jobs": jobs, "total": total})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	j, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		middleware.Error(w, http.StatusNotFound, "job not found")
		return
	}

	middleware.JSON(w, http.StatusOK, j)
}

func (h *Handler) GetResults(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "jobID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid job ID")
		return
	}

	results, err := h.store.ListResults(r.Context(), id)
	if err != nil {
		middleware.Error(w, http.StatusInternalServerError, "failed to list job results")
		return
	}

	middleware.JSON(w, http.StatusOK, map[string]any{"results": results})
}
