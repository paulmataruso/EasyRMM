package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/coder/websocket"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// DialChannel opens the agent's WebSocket channel (ADR-0059): a signed GET
// with the subprotocol easyrmm-agent.v1, over HTTP/1.1 on the route's own
// connection. It returns the connection and the nonce of the upgrade
// request, which the server's hello repeats. Any answer but 101 is an
// *Error.
func (c *Client) DialChannel(ctx context.Context) (*websocket.Conn, string, error) {
	if c.key == nil {
		return nil, "", errors.New("the agent is not enrolled")
	}
	h, err := agentproto.Sign(c.key, c.device, http.MethodGet, agentproto.PathChannel, nil, c.now())
	if err != nil {
		return nil, "", err
	}
	a, _ := agentproto.Parse(h) // what Sign wrote parses
	u := *c.base
	u.Scheme = "ws"
	if c.base.Scheme == "https" {
		u.Scheme = "wss"
	}
	u.Path = agentproto.PathChannel
	ws, resp, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{
		HTTPClient:      c.ws.Load(),
		HTTPHeader:      http.Header{"Authorization": {h}, "User-Agent": {c.agent}},
		Subprotocols:    []string{agentproto.ChannelSubprotocol},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if resp == nil || resp.StatusCode == http.StatusSwitchingProtocols {
			return nil, "", err
		}
		defer func() { _ = resp.Body.Close() }()
		e := &Error{Status: resp.StatusCode}
		var env struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if b, rerr := io.ReadAll(io.LimitReader(resp.Body, 64<<10)); rerr == nil && json.Unmarshal(b, &env) == nil {
			e.Code, e.Message = env.Error.Code, env.Error.Message
		}
		if s, perr := strconv.Atoi(resp.Header.Get("Retry-After")); perr == nil && s > 0 {
			e.RetryAfter = time.Duration(s) * time.Second
		}
		return nil, "", e
	}
	if ws.Subprotocol() != agentproto.ChannelSubprotocol {
		_ = ws.CloseNow()
		return nil, "", errors.New("the server did not accept the channel's subprotocol")
	}
	ws.SetReadLimit(agentproto.MaxChannelBigFrame)
	return ws, a.Nonce, nil
}
