package agent

import (
	"log/slog"
	"sync"
)

type Hub struct {
	mu      sync.RWMutex
	clients map[string]*Client
	logger  *slog.Logger
}

func NewHub(logger *slog.Logger) *Hub {
	return &Hub{
		clients: make(map[string]*Client),
		logger:  logger,
	}
}

func (h *Hub) Register(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c.AgentID] = c
	h.logger.Info("agent connected", "agent_id", c.AgentID)
}

func (h *Hub) Unregister(c *Client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if existing, ok := h.clients[c.AgentID]; ok && existing == c {
		delete(h.clients, c.AgentID)
		h.logger.Info("agent disconnected", "agent_id", c.AgentID)
	}
}

func (h *Hub) GetClient(agentID string) *Client {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.clients[agentID]
}

func (h *Hub) ConnectedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) ConnectedAgentIDs() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ids := make([]string, 0, len(h.clients))
	for id := range h.clients {
		ids = append(ids, id)
	}
	return ids
}
