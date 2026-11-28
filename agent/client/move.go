package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// ConfirmAddress asks the address this client was made for whether it is the
// server the agent trusts (ADR-0061): it sends a request signed with the
// device key, to be answered with a confirmation signed with a job key the
// agent trusts, over the device, this request's nonce and the address. Any
// other answer is a failed check: a 404 from a server that predates the
// route, a redirect (the client is to follow none, Options.NoRedirect), a
// certificate the agent does not trust, a confirmation that does not verify.
// An error that wraps one of agentproto's ErrAddress values means the server
// answered and the answer was wrong.
func (c *Client) ConfirmAddress(ctx context.Context, keys agentproto.Keys) error {
	address, err := agentproto.MoveTarget(c.base.String())
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("no server key is pinned to check %s with", address)
	}
	body, err := json.Marshal(agentproto.AddressRequest{Address: address})
	if err != nil {
		return err
	}
	resp, nonce, err := c.send(ctx, http.MethodPost, agentproto.PathAddress, body, true)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var ans agentproto.AddressAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&ans); err != nil {
		return fmt.Errorf("reading the server's answer: %w", err)
	}
	return agentproto.VerifyAddress(keys, ans, c.device, nonce, address)
}

// Moved reports that the agent changed address, or why it could not
// (ADR-0061), at the address the client was made for. A server that predates
// the route answers 404, an *Error the caller drops.
func (c *Client) Moved(ctx context.Context, r agentproto.MoveReport) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, agentproto.PathMove, body, true)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.Body.Close()
}
