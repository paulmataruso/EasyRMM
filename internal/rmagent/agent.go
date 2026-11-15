package rmagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type Agent struct {
	cfg    *Config
	logger *slog.Logger
	client *http.Client
}

func New(cfg *Config, logger *slog.Logger) (*Agent, error) {
	return &Agent{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if a.cfg.AgentID == "" || a.cfg.AgentToken == "" {
		if a.cfg.EnrollToken == "" {
			return fmt.Errorf("agent not enrolled and no enrollment token provided")
		}
		if err := a.enroll(ctx); err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}
	}

	a.logger.Info("agent starting", "agent_id", a.cfg.AgentID, "server", a.cfg.ServerURL)

	for {
		err := a.connectAndRun(ctx)
		if ctx.Err() != nil {
			return nil
		}
		a.logger.Warn("connection lost, reconnecting in 10s", "error", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(10 * time.Second):
		}
	}
}

func (a *Agent) enroll(ctx context.Context) error {
	hostname, _ := os.Hostname()

	body := map[string]string{
		"enrollment_token": a.cfg.EnrollToken,
		"hostname":         hostname,
		"os_type":          runtime.GOOS,
		"arch":             runtime.GOARCH,
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.cfg.ServerURL+"/api/v1/agent/enroll", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("enroll request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("enrollment failed (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		AgentID    string `json:"agent_id"`
		AgentToken string `json:"agent_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode enrollment response: %w", err)
	}

	a.cfg.AgentID = result.AgentID
	a.cfg.AgentToken = result.AgentToken

	if a.cfg.ConfigPath != "" {
		if err := a.cfg.Save(a.cfg.ConfigPath); err != nil {
			a.logger.Warn("failed to save config", "error", err)
		}
	}

	a.logger.Info("enrolled successfully", "agent_id", a.cfg.AgentID)
	return nil
}

func (a *Agent) connectAndRun(ctx context.Context) error {
	wsURL := strings.Replace(a.cfg.ServerURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)

	params := url.Values{}
	params.Set("agent_id", a.cfg.AgentID)
	params.Set("token", a.cfg.AgentToken)

	conn, _, err := websocket.DefaultDialer.DialContext(ctx,
		wsURL+"/ws/agent?"+params.Encode(), nil)
	if err != nil {
		return fmt.Errorf("websocket connect: %w", err)
	}
	defer conn.Close()

	a.logger.Info("connected to server")

	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	telemetryTicker := time.NewTicker(5 * time.Minute)
	defer telemetryTicker.Stop()

	msgCh := make(chan message)
	errCh := make(chan error, 1)

	go func() {
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				errCh <- err
				return
			}
			var msg message
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			msgCh <- msg
		}
	}()

	if err := a.sendTelemetry(conn); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			conn.WriteMessage(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return nil

		case err := <-errCh:
			return err

		case msg := <-msgCh:
			a.handleServerMessage(conn, msg)

		case <-heartbeatTicker.C:
			if err := sendMsg(conn, message{Type: "heartbeat"}); err != nil {
				return err
			}

		case <-telemetryTicker.C:
			if err := a.sendTelemetry(conn); err != nil {
				return err
			}
		}
	}
}

func (a *Agent) handleServerMessage(conn *websocket.Conn, msg message) {
	switch msg.Type {
	case "heartbeat_ack":
		// expected
	case "run_script":
		a.logger.Info("script execution requested", "msg_id", msg.ID)
	case "ping":
		sendMsg(conn, message{Type: "pong", ID: msg.ID})
	default:
		a.logger.Debug("unknown server message", "type", msg.Type)
	}
}

func (a *Agent) sendTelemetry(conn *websocket.Conn) error {
	hostname, _ := os.Hostname()
	telemetry := map[string]any{
		"hostname":      hostname,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"agent_version": a.cfg.Version,
		"num_cpu":       runtime.NumCPU(),
	}
	data, _ := json.Marshal(telemetry)
	return sendMsg(conn, message{Type: "telemetry", Payload: data})
}

type message struct {
	Type    string          `json:"type"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func sendMsg(conn *websocket.Conn, msg message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, data)
}
