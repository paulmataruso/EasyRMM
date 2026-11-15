package device

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
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

type DeviceFilter struct {
	OrgID    *uuid.UUID
	SiteID   *uuid.UUID
	GroupID  *uuid.UUID
	Status   string
	OSType   string
	Search   string
	Page     int
	PageSize int
	SortBy   string
	SortDir  string
}

func parseDeviceFilter(r *http.Request) DeviceFilter {
	f := DeviceFilter{
		Page:     1,
		PageSize: 50,
		SortBy:   "hostname",
		SortDir:  "asc",
	}

	if v := r.URL.Query().Get("org_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.OrgID = &id
		}
	}
	if v := r.URL.Query().Get("site_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.SiteID = &id
		}
	}
	if v := r.URL.Query().Get("group_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.GroupID = &id
		}
	}
	if v := r.URL.Query().Get("status"); v != "" {
		f.Status = v
	}
	if v := r.URL.Query().Get("os_type"); v != "" {
		f.OSType = v
	}
	if v := r.URL.Query().Get("search"); v != "" {
		f.Search = strings.TrimSpace(v)
	}
	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			f.Page = p
		}
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		if ps, err := strconv.Atoi(v); err == nil && ps > 0 && ps <= 200 {
			f.PageSize = ps
		}
	}
	if v := r.URL.Query().Get("sort_by"); v != "" {
		allowed := map[string]bool{"hostname": true, "status": true, "os_type": true, "last_seen_at": true, "created_at": true}
		if allowed[v] {
			f.SortBy = v
		}
	}
	if v := r.URL.Query().Get("sort_dir"); v != "" {
		if v == "desc" {
			f.SortDir = "desc"
		}
	}

	return f
}

type deviceListResponse struct {
	Devices    []models.Device `json:"devices"`
	Total      int             `json:"total"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	TotalPages int             `json:"total_pages"`
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	filter := parseDeviceFilter(r)

	if filter.OrgID == nil {
		middleware.Error(w, http.StatusBadRequest, "org_id query parameter is required")
		return
	}

	storeFilter := ListFilters{
		SiteID:        filter.SiteID,
		DeviceGroupID: filter.GroupID,
		Status:        filter.Status,
		OSType:        filter.OSType,
		Search:        filter.Search,
		SortBy:        filter.SortBy,
		SortDir:       filter.SortDir,
		Limit:         filter.PageSize,
		Offset:        (filter.Page - 1) * filter.PageSize,
	}

	devices, total, err := h.store.ListByOrganization(r.Context(), *filter.OrgID, storeFilter)
	if err != nil {
		h.logger.Error("failed to list devices", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to list devices")
		return
	}

	totalPages := (total + filter.PageSize - 1) / filter.PageSize
	middleware.JSON(w, http.StatusOK, deviceListResponse{
		Devices:    devices,
		Total:      total,
		Page:       filter.Page,
		PageSize:   filter.PageSize,
		TotalPages: totalPages,
	})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "deviceID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	dev, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		middleware.Error(w, http.StatusNotFound, "device not found")
		return
	}

	middleware.JSON(w, http.StatusOK, dev)
}

type updateDeviceRequest struct {
	DisplayName      *string        `json:"display_name,omitempty"`
	DeviceGroupID    *uuid.UUID     `json:"device_group_id,omitempty"`
	Tags             []string       `json:"tags,omitempty"`
	CustomProperties map[string]any `json:"custom_properties,omitempty"`
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "deviceID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	var req updateDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dev, err := h.store.UpdateMeta(r.Context(), id, UpdateMetaParams{
		DisplayName:      req.DisplayName,
		DeviceGroupID:    req.DeviceGroupID,
		Tags:             req.Tags,
		CustomProperties: req.CustomProperties,
	})
	if err != nil {
		h.logger.Error("failed to update device", "error", err, "id", id)
		middleware.Error(w, http.StatusInternalServerError, "failed to update device")
		return
	}

	user := middleware.UserFromContext(r.Context())
	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:         &user.ID,
		OrganizationID: &dev.OrganizationID,
		DeviceID:       &dev.ID,
		Action:         "device.update",
		ResourceType:   "device",
		ResourceID:     dev.ID.String(),
		IPAddress:      r.RemoteAddr,
	})

	middleware.JSON(w, http.StatusOK, dev)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "deviceID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	dev, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		middleware.Error(w, http.StatusNotFound, "device not found")
		return
	}

	if err := h.store.Delete(r.Context(), id); err != nil {
		h.logger.Error("failed to delete device", "error", err, "id", id)
		middleware.Error(w, http.StatusInternalServerError, "failed to delete device")
		return
	}

	user := middleware.UserFromContext(r.Context())
	h.auditStore.Log(r.Context(), models.AuditLog{
		UserID:         &user.ID,
		OrganizationID: &dev.OrganizationID,
		DeviceID:       &dev.ID,
		Action:         "device.delete",
		ResourceType:   "device",
		ResourceID:     id.String(),
		IPAddress:      r.RemoteAddr,
	})

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	orgIDStr := r.URL.Query().Get("org_id")
	if orgIDStr == "" {
		middleware.Error(w, http.StatusBadRequest, "org_id query parameter is required")
		return
	}

	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid org_id")
		return
	}

	stats, err := h.store.CountByStatus(r.Context(), &orgID)
	if err != nil {
		h.logger.Error("failed to get device stats", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to get device stats")
		return
	}

	middleware.JSON(w, http.StatusOK, stats)
}
