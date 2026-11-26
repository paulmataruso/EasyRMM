package client

import (
	"context"
	"encoding/json"

	"github.com/paulmataruso/easyrmm/internal/qaticket"
)

// QAEnrollRequest, QAEnrollResult, QAState and QACleanup are the Quick
// Assist runner's messages (ADR-0080); they are the server's types on the
// wire, kept here as JSON so the agent does not import the server.
type QAEnrollRequest struct {
	Ticket    string  `json:"ticket"`
	PublicKey string  `json:"publicKey"`
	Code      string  `json:"code"`
	Consent   bool    `json:"consent"`
	Facts     QAFacts `json:"facts"`
}

// QAFacts are what the runner says about its computer.
type QAFacts struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Platform string `json:"platform"`
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	Elevated bool   `json:"elevated"`
}

// QAEnrollResult is the server's answer to a runner.
type QAEnrollResult struct {
	DeviceID         string `json:"deviceId"`
	SessionID        string `json:"sessionId"`
	HeartbeatSeconds int    `json:"heartbeatSeconds"`
	Organization     string `json:"organization"`
}

// QAState is the session's state as the runner sees it.
type QAState struct {
	State     string `json:"state"`
	EndReason string `json:"endReason"`
}

// QACheck is one check of a cleanup report.
type QACheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// QACleanup is the runner's report of what it removed.
type QACleanup struct {
	Result         string    `json:"result"`
	Checks         []QACheck `json:"checks"`
	ManifestSHA256 string    `json:"manifestSha256"`
}

// QAEnroll starts a session from a ticket. It is not signed: the ticket is
// the proof, and the answer names the identity to sign with.
func (c *Client) QAEnroll(ctx context.Context, req QAEnrollRequest) (*QAEnrollResult, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var out QAEnrollResult
	if err := c.call(ctx, "POST", qaticket.PathEnroll, body, false, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// QAStatus asks where the session stands; it also tells the server the
// runner is alive.
func (c *Client) QAStatus(ctx context.Context) (*QAState, error) {
	var out QAState
	if err := c.call(ctx, "POST", qaticket.PathStatus, []byte("{}"), true, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// QAEnd reports the end of the session and its cleanup.
func (c *Client) QAEnd(ctx context.Context, reason string, rep *QACleanup) error {
	body, err := json.Marshal(map[string]any{"reason": reason, "cleanup": rep})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, "POST", qaticket.PathEnd, body, true)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
