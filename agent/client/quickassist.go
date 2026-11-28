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
	JobKey           string `json:"jobKey"`
	DeviceID         string `json:"deviceId"`
	SessionID        string `json:"sessionId"`
	HeartbeatSeconds int    `json:"heartbeatSeconds"`
	Organization     string `json:"organization"`
}

// QAState is the session's state as the runner sees it.
type QAState struct {
	State     string   `json:"state"`
	EndReason string   `json:"endReason"`
	Install   string   `json:"install"`
	Offer     *QAOffer `json:"offer"`
	// EasyPatchToken and EasyPatchServer are what the EasyPatch agent of an
	// elevated session enrolls with; empty when none is offered.
	EasyPatchToken  string `json:"easypatchToken"`
	EasyPatchServer string `json:"easypatchServer"`
}

// QAOffer names what the user is asked to keep.
type QAOffer struct {
	Organization string `json:"organization"`
	Site         string `json:"site"`
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

// QAMesh tells the server which MeshAgent node this session started.
func (c *Client) QAMesh(ctx context.Context, nodeID string) error {
	body, err := json.Marshal(map[string]string{"nodeId": nodeID})
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, "POST", qaticket.PathMesh, body, true)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// QAInstall tells the server the user's answer to "keep the agent". On yes
// the answer carries the token for the one enrollment that installs it.
func (c *Client) QAInstall(ctx context.Context, accept bool) (string, error) {
	body, err := json.Marshal(map[string]bool{"accept": accept})
	if err != nil {
		return "", err
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := c.call(ctx, "POST", qaticket.PathInstall, body, true, &out); err != nil {
		return "", err
	}
	return out.Token, nil
}

// QAConverted reports that the permanent agent is in place.
func (c *Client) QAConverted(ctx context.Context) error {
	resp, err := c.do(ctx, "POST", qaticket.PathConverted, []byte("{}"), true)
	if err != nil {
		return err
	}
	return resp.Body.Close()
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
