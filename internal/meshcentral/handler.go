package meshcentral

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/paulmataruso/easyrm/internal/auth"
	"github.com/paulmataruso/easyrm/internal/device"
	"github.com/paulmataruso/easyrm/pkg/middleware"
)

type Handler struct {
	client      *Client
	deviceStore *device.Store
	logger      *slog.Logger
}

func NewHandler(client *Client, deviceStore *device.Store, logger *slog.Logger) *Handler {
	return &Handler{
		client:      client,
		deviceStore: deviceStore,
		logger:      logger,
	}
}

func (h *Handler) GetRemoteAccessToken(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		middleware.Error(w, http.StatusUnauthorized, "authentication required")
		return
	}

	deviceID, err := uuid.Parse(chi.URLParam(r, "deviceID"))
	if err != nil {
		middleware.Error(w, http.StatusBadRequest, "invalid device ID")
		return
	}

	dev, err := h.deviceStore.GetByID(r.Context(), deviceID)
	if err != nil {
		middleware.Error(w, http.StatusNotFound, "device not found")
		return
	}

	if dev.MeshNodeID == "" {
		middleware.Error(w, http.StatusBadRequest, "device has no MeshCentral node ID")
		return
	}

	tokenLifetime := int(h.client.cfg.TokenLifetime.Minutes())
	if tokenLifetime == 0 {
		tokenLifetime = 60
	}

	token, err := h.client.GenerateLoginToken(r.Context(), h.client.cfg.AdminUser, tokenLifetime)
	if err != nil {
		h.logger.Error("failed to generate mesh login token", "error", err)
		middleware.Error(w, http.StatusInternalServerError, "failed to generate remote access token")
		return
	}

	connectURL := h.client.cfg.URL + "/?login=" + token + "&node=" + dev.MeshNodeID

	resp := struct {
		URL       string    `json:"url"`
		Token     string    `json:"token"`
		NodeID    string    `json:"node_id"`
		ExpiresAt time.Time `json:"expires_at"`
	}{
		URL:       connectURL,
		Token:     token,
		NodeID:    dev.MeshNodeID,
		ExpiresAt: time.Now().Add(time.Duration(tokenLifetime) * time.Minute),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) GetMeshConfig(w http.ResponseWriter, r *http.Request) {
	resp := struct {
		URL          string `json:"url"`
		FrameAllowed bool   `json:"frame_allowed"`
	}{
		URL:          h.client.cfg.URL,
		FrameAllowed: true,
	}
	middleware.JSON(w, http.StatusOK, resp)
}
