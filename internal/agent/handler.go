package agent

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/websocket"

	"github.com/paulmataruso/easyrm/internal/device"
	"github.com/paulmataruso/easyrm/pkg/middleware"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

type Handler struct {
	hub         *Hub
	deviceStore *device.Store
	logger      *slog.Logger
}

func NewHandler(hub *Hub, deviceStore *device.Store, logger *slog.Logger) *Handler {
	return &Handler{
		hub:         hub,
		deviceStore: deviceStore,
		logger:      logger,
	}
}

func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	agentToken := r.URL.Query().Get("token")

	if agentID == "" || agentToken == "" {
		middleware.Error(w, http.StatusBadRequest, "agent_id and token are required")
		return
	}

	dev, err := h.deviceStore.GetByAgentID(r.Context(), agentID)
	if err != nil || dev == nil {
		middleware.Error(w, http.StatusUnauthorized, "unknown agent")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logger.Error("websocket upgrade failed", "error", err)
		return
	}

	client := NewClient(h.hub, conn, agentID, h.logger)

	h.deviceStore.UpdateStatus(r.Context(), dev.ID, "online")
	h.deviceStore.UpdateLastSeen(r.Context(), dev.ID)

	client.Run(r.Context())

	h.deviceStore.UpdateStatus(r.Context(), dev.ID, "offline")
}
