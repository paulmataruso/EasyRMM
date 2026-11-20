package easypatch

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// The calls behind a device's Patches tab beyond scans and installs
// (one-product plan, C1): exclusions, the install preview, removing an
// update, messages to users and agent updates.

// Exclude keeps an update off an endpoint: EasyPatch does not install it
// there, and it no longer counts against the endpoint's compliance.
// Excluding it again changes nothing.
func (c *Client) Exclude(ctx context.Context, endpointID, updateGUID uuid.UUID, reason, onBehalfOf string) error {
	body := struct {
		UpdateGUID uuid.UUID `json:"updateGuid"`
		Reason     *string   `json:"reason"`
	}{UpdateGUID: updateGUID}
	if reason != "" {
		body.Reason = &reason
	}
	return c.do(ctx, http.MethodPost, "/api/v1/endpoints/"+endpointID.String()+"/exclusions", nil, body, onBehalfOf, nil)
}

// Include undoes Exclude. Including an update that is not excluded changes
// nothing.
func (c *Client) Include(ctx context.Context, endpointID, updateGUID uuid.UUID, onBehalfOf string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/endpoints/"+endpointID.String()+"/exclusions/"+updateGUID.String(), nil, nil, onBehalfOf, nil)
}

// PreviewItem is an update an install would install.
type PreviewItem struct {
	UpdateGUID uuid.UUID `json:"updateGuid"`
	Title      string    `json:"title"`
	KbNumber   string    `json:"kbNumber"`
	Category   string    `json:"category"`
	SizeBytes  *int64    `json:"sizeBytes"`
	// RebootBehavior above 0 means the update is likely to need a restart.
	RebootBehavior *int   `json:"rebootBehavior"`
	State          string `json:"state"`
}

// PreviewSkip is an update an install would leave out, and why.
type PreviewSkip struct {
	UpdateGUID uuid.UUID `json:"updateGuid"`
	Title      string    `json:"title"`
	KbNumber   string    `json:"kbNumber"`
	Category   string    `json:"category"`
	Reason     string    `json:"reason"`
}

// PreviewFilter is the part of the endpoint's policy an install applies.
type PreviewFilter struct {
	Categories      []string `json:"categories"`
	IncludeOptional bool     `json:"includeOptional"`
}

// InstallPreview is what an install would do on an endpoint, from its last
// scan; the agent scans again before installing.
type InstallPreview struct {
	// Mode is AllEligible or Selected.
	Mode              string         `json:"mode"`
	Items             []PreviewItem  `json:"items"`
	Skipped           []PreviewSkip  `json:"skipped"`
	TotalSizeBytes    int64          `json:"totalSizeBytes"`
	RebootLikelyCount int            `json:"rebootLikelyCount"`
	Warnings          []string       `json:"warnings"`
	Filter            *PreviewFilter `json:"filter"`
	LastScanAt        *time.Time     `json:"lastScanAt"`
}

// InstallPreview asks what installing on an endpoint would do: every
// eligible update when guids is empty, those otherwise.
func (c *Client) InstallPreview(ctx context.Context, endpointID uuid.UUID, guids []uuid.UUID) (InstallPreview, error) {
	q := url.Values{"mode": {"all"}}
	if len(guids) > 0 {
		ids := make([]string, len(guids))
		for i, g := range guids {
			ids[i] = g.String()
		}
		q.Set("mode", "selected")
		q.Set("updateGuids", strings.Join(ids, ","))
	}
	var p InstallPreview
	err := c.do(ctx, http.MethodGet, "/api/v1/endpoints/"+endpointID.String()+"/install-preview", q, nil, "", &p)
	return p, err
}

// RemoveUpdate has an endpoint uninstall an installed update. block also
// excludes it, so that EasyPatch does not install it again. The agent never
// restarts the computer for it.
func (c *Client) RemoveUpdate(ctx context.Context, endpointID, updateGUID uuid.UUID, block bool, reason, onBehalfOf string) (Job, error) {
	body := struct {
		Block  bool    `json:"block"`
		Reason *string `json:"reason"`
	}{Block: block}
	if reason != "" {
		body.Reason = &reason
	}
	var j Job
	err := c.do(ctx, http.MethodPost, "/api/v1/endpoints/"+endpointID.String()+"/updates/"+updateGUID.String()+"/uninstall", nil, body, onBehalfOf, &j)
	return j, err
}

// MessagePreset is a message EasyPatch can show to users. There is no free
// text: only these.
type MessagePreset struct {
	Preset string `json:"preset"`
	Title  string `json:"title"`
	// Body holds "{time}" where NeedsRestartTime fills in a time.
	Body             string `json:"body"`
	NeedsRestartTime bool   `json:"needsRestartTime"`
}

// MessagePresets lists the messages EasyPatch can show.
func (c *Client) MessagePresets(ctx context.Context) ([]MessagePreset, error) {
	var list []MessagePreset
	err := c.do(ctx, http.MethodGet, "/api/v1/user-messages", nil, nil, "", &list)
	return list, err
}

// Message is a preset to show, with the restart time it names, if any.
type Message struct {
	Preset    string     `json:"preset"`
	RestartAt *time.Time `json:"restartAt"`
}

// BulkNotify shows a message to the users signed in to endpoints. Agents
// without a tray (Linux, macOS, Windows before 1.1.0) cannot, and are
// reported as failed.
func (c *Client) BulkNotify(ctx context.Context, ids []uuid.UUID, m Message, onBehalfOf string) (BulkResult, error) {
	var r BulkResult
	body := struct {
		EndpointIDs []uuid.UUID `json:"endpointIds"`
		Message     Message     `json:"message"`
	}{ids, m}
	err := c.do(ctx, http.MethodPost, "/api/v1/endpoints/bulk/notify", nil, body, onBehalfOf, &r)
	return r, err
}

// BulkAgentUpdate has endpoints' agents update themselves to the newest
// package EasyPatch hosts whose release signature they accept.
func (c *Client) BulkAgentUpdate(ctx context.Context, ids []uuid.UUID, onBehalfOf string) (BulkResult, error) {
	var r BulkResult
	body := struct {
		EndpointIDs []uuid.UUID `json:"endpointIds"`
		Version     *string     `json:"version"`
	}{EndpointIDs: ids}
	err := c.do(ctx, http.MethodPost, "/api/v1/endpoints/bulk/agent-update", nil, body, onBehalfOf, &r)
	return r, err
}
