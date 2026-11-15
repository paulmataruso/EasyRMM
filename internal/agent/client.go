package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait  = 10 * time.Second
	pongWait   = 60 * time.Second
	pingPeriod = 50 * time.Second
	maxMsgSize = 512 * 1024
)

type Message struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type Client struct {
	AgentID string
	conn    *websocket.Conn
	hub     *Hub
	send    chan []byte
	done    chan struct{}
	once    sync.Once
	logger  *slog.Logger
}

func NewClient(hub *Hub, conn *websocket.Conn, agentID string, logger *slog.Logger) *Client {
	return &Client{
		AgentID: agentID,
		conn:    conn,
		hub:     hub,
		send:    make(chan []byte, 64),
		done:    make(chan struct{}),
		logger:  logger,
	}
}

func (c *Client) Run(ctx context.Context) {
	c.hub.Register(c)
	defer c.hub.Unregister(c)

	go c.writePump()
	c.readPump(ctx)
}

func (c *Client) Send(msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	select {
	case c.send <- data:
		return nil
	default:
		return ErrBufferFull
	}
}

func (c *Client) Close() {
	c.once.Do(func() {
		close(c.done)
		c.conn.Close()
	})
}

func (c *Client) readPump(ctx context.Context) {
	defer c.Close()

	c.conn.SetReadLimit(maxMsgSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				c.logger.Warn("websocket read error", "agent_id", c.AgentID, "error", err)
			}
			return
		}

		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			c.logger.Warn("invalid message", "agent_id", c.AgentID, "error", err)
			continue
		}

		c.handleMessage(ctx, msg)
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Close()
	}()

	for {
		select {
		case data, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, nil)
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) handleMessage(ctx context.Context, msg Message) {
	switch msg.Type {
	case "heartbeat":
		c.Send(Message{Type: "heartbeat_ack", ID: msg.ID})
	case "telemetry":
		c.logger.Debug("telemetry received", "agent_id", c.AgentID)
	case "job_result":
		c.logger.Debug("job result received", "agent_id", c.AgentID, "msg_id", msg.ID)
	default:
		c.logger.Warn("unknown message type", "agent_id", c.AgentID, "type", msg.Type)
	}
}
