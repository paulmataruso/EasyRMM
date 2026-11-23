package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/logship"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// shipLogs sets up the agent's log records for the server (ADR-0069): a
// buffer in the state folder, the agent's logger at a level the server can
// raise for a while, and the EasyPatch agent's log and MeshAgent's read for
// it. It replaces e.log. Without a usable buffer the agent logs as before
// and sends nothing.
func (e *env) shipLogs() *logship.Shipper {
	dir := filepath.Join(e.store.Dir(), "logs")
	buf, err := logship.OpenBuffer(dir, logship.DefaultMaxBytes, time.Now())
	if err != nil {
		e.log.Warn("the log buffer could not be opened; logs are not sent to the server", "error", err)
		return nil
	}
	s := logship.New(buf)
	offsets := logship.OpenOffsets(dir)
	s.Tails = []*logship.Tail{
		{Source: agentproto.LogSourceEasyPatch, Path: e.paths.EasyPatchLog(), Offsets: offsets},
		{Source: agentproto.LogSourceMeshAgent, Path: e.paths.MeshAgentLog(), Offsets: offsets},
	}
	s.Log = e.log
	e.log = slog.New(logship.NewHandler(e.log.Handler(), s))
	return s
}

// sendLogs sends a batch through the client; a server without the endpoint
// answers 404.
func sendLogs(c *client.Client) logship.SendFunc {
	return func(ctx context.Context, b agentproto.LogBatch) (agentproto.LogAck, error) {
		ack, err := c.AgentLogs(ctx, b)
		var ce *client.Error
		if errors.As(err, &ce) && ce.Status == http.StatusNotFound {
			return ack, logship.ErrUnsupported
		}
		return ack, err
	}
}
