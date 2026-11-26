package agentapi

import (
	"context"
	"net"
	"net/http"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/tlstrust"
)

// Trust asks agents to verify certificate chains and takes their answers
// (tlstrust.Service, ADR-0055).
type Trust interface {
	Heartbeat(ctx context.Context, d tlstrust.Device, b tlstrust.Beat) *agentproto.SignedTrust
}

// WithTrust has heartbeats carry the trust instruction of an agent that
// announced it, and take the agent's report of the last one.
func (a *API) WithTrust(t Trust) *API {
	a.trust = t
	return a
}

// originHost is the host name a request arrived at, lower case, without its
// port: the origin an agent's signed requests go to.
func originHost(r *http.Request) string {
	h := r.Host
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func (a *API) trustHeartbeat(r *http.Request, d *agents.Device, in agentproto.HeartbeatRequest) *agentproto.SignedTrust {
	return a.trust.Heartbeat(r.Context(), tlstrust.Device{ID: d.ID, Org: d.OrganizationID, Site: d.SiteID, Hostname: d.Hostname, Platform: in.Facts.Platform},
		tlstrust.Beat{Origin: originHost(r), IP: httpapi.ClientIP(r), Caps: in.Caps, AgentSHA256: in.Facts.AgentSHA256, Report: in.Trust})
}
