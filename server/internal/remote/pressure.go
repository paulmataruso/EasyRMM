package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// PressurePath tells the session view how long the gateway has held a
// device's desktop pictures back because MeshCentral was not reading them
// (ADR-0025). MeshCentral stops reading the agent when a viewer falls
// behind; the session view then asks the agent for pictures less often
// until the viewer keeps up. MeshCentral has no route under /.easyrmm/.
const PressurePath = "/.easyrmm/pressure"

// nodePressure is the time the gateway held one device's desktop pictures.
type nodePressure struct {
	held atomic.Int64 // nanoseconds, only ever growing
	// conns counts the device's open agent desktop relays; guarded by
	// Gateway.mu.
	conns int
}

type grantKey struct {
	session uuid.UUID
	node    string
}

// holdPressure returns the device's counter, counting one more relay.
func (g *Gateway) holdPressure(node string) *nodePressure {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.pressure[node]
	if p == nil {
		p = &nodePressure{}
		g.pressure[node] = p
	}
	p.conns++
	return p
}

// releasePressure counts one relay less, forgetting the counter after the
// last.
func (g *Gateway) releasePressure(node string, p *nodePressure) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p.conns--
	if p.conns <= 0 && g.pressure[node] == p {
		delete(g.pressure, node)
	}
}

func (g *Gateway) heldFor(node string) (time.Duration, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.pressure[node]
	if p == nil {
		return 0, false
	}
	return time.Duration(p.held.Load()), true
}

// servePressure answers the session view of a desktop session: the total
// time the device's pictures were held so far, while it has a relay open.
func (g *Gateway) servePressure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	session, ok := g.authorize(r)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	node, err := normalizeNodeID(r.URL.Query().Get("node"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	granted, err := g.desktopGranted(r.Context(), session, node)
	if err != nil {
		httpapi.LoggerFrom(r.Context()).Error("remote gateway: checking a desktop grant failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !granted {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	held, active := g.heldFor(node)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Held   int64 `json:"held"`
		Active bool  `json:"active"`
	}{held.Milliseconds(), active})
}

// desktopGranted reports whether the session opened a desktop session on
// the device, remembering a yes for the cache lifetime: the session view
// asks twice a second.
func (g *Gateway) desktopGranted(ctx context.Context, session uuid.UUID, node string) (bool, error) {
	key := grantKey{session, node}
	now := time.Now()
	g.mu.Lock()
	until, ok := g.grants[key]
	g.mu.Unlock()
	if ok && now.Before(until) {
		return true, nil
	}
	if g.granted == nil {
		return false, nil
	}
	ok, err := g.granted(ctx, session, node, KindDesktop)
	if err != nil || !ok {
		return false, err
	}
	g.mu.Lock()
	g.grants[key] = now.Add(g.ttl)
	g.mu.Unlock()
	return true, nil
}
