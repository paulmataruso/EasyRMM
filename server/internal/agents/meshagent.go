package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
)

// MeshAgentCacheFor is how long the server keeps a MeshAgent binary it
// fetched from MeshCentral. It must hold the whole binary to sign it before
// sending it, and a fleet installing at once then costs MeshCentral one
// download per platform.
const MeshAgentCacheFor = 10 * time.Minute

// MeshHostCacheFor is how long the server remembers the MeshCentral host of
// the settings it hands out for a site, and MeshHostRetry how long it
// remembers that it could not read it.
const (
	MeshHostCacheFor = 10 * time.Minute
	MeshHostRetry    = time.Minute
)

type meshHost struct {
	host     string // "" when unknown
	at       time.Time
	ok       bool // MeshCentral answered
	fetching bool
}

// meshHosts remembers each site's expected MeshCentral host.
type meshHosts struct {
	mu    sync.Mutex
	sites map[uuid.UUID]meshHost
}

// MeshState is what the server stores of an agent's report about MeshAgent
// (ADR-0069): the report, and whether the MeshCentral host in its settings
// is the one the server hands out, nil when the server could not tell.
type MeshState struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Host      string `json:"host,omitempty"`
	Error     string `json:"error,omitempty"`
	HostOK    *bool  `json:"hostOk"`
}

// meshState cleans an agent's report about MeshAgent and judges its host.
func (s *Service) meshState(ctx context.Context, site uuid.UUID, in agentproto.MeshAgentState) []byte {
	st := MeshState{Installed: in.Installed, Running: in.Running, Host: clean(in.Host, agentproto.MaxMeshHost),
		Error: clean(in.Error, agentproto.MaxMeshAgentError)}
	if st.Host != "" {
		if want := s.expectedMeshHost(ctx, site); want != "" {
			ok := want == st.Host
			st.HostOK = &ok
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		return nil // strings and booleans: it encodes
	}
	return b
}

// expectedMeshHost is the host of the settings the server hands a site's
// devices, "" when it is not known: MeshCentral is not there to ask, or
// another heartbeat is asking now (a fleet's heartbeats are never held up
// for it, and the answer is cached).
func (s *Service) expectedMeshHost(ctx context.Context, site uuid.UUID) string {
	if s.mesh == nil {
		return ""
	}
	h := &s.meshHosts
	h.mu.Lock()
	e := h.sites[site]
	ttl := MeshHostRetry
	if e.ok {
		ttl = MeshHostCacheFor
	}
	if e.fetching || (!e.at.IsZero() && s.now().Sub(e.at) < ttl) {
		h.mu.Unlock()
		return e.host
	}
	if h.sites == nil {
		h.sites = map[uuid.UUID]meshHost{}
	}
	e.fetching = true
	h.sites[site] = e
	h.mu.Unlock()

	group, err := s.mesh.Group(ctx, site)
	var b []byte
	if err == nil && group != "" {
		b, err = s.mesh.Settings(ctx, group)
	}
	e = meshHost{at: s.now(), ok: err == nil && group != ""}
	if e.ok {
		e.host = agentproto.MeshServerHost(b)
	}
	h.mu.Lock()
	h.sites[site] = e
	h.mu.Unlock()
	return e.host
}

// meshCache keeps MeshAgent binaries by MeshCentral architecture number.
type meshCache struct {
	mu   sync.Mutex
	bins map[int]meshBinary
}

type meshBinary struct {
	body []byte
	at   time.Time
}

// MeshAgentBinary returns the MeshAgent build for a platform (Go's GOOS and
// GOARCH names), from the MeshCentral this server runs.
func (s *Service) MeshAgentBinary(ctx context.Context, goos, goarch string) ([]byte, error) {
	if s.mesh == nil {
		return nil, ErrMeshUnavailable
	}
	arch := agentproto.MeshArch(goos, goarch)
	if arch == 0 {
		return nil, apperr.Invalid("arch", "MeshAgent is not available for this platform.")
	}
	// One fetch at a time: agents asking meanwhile wait for it and share it.
	s.meshBins.mu.Lock()
	defer s.meshBins.mu.Unlock()
	if b, ok := s.meshBins.bins[arch]; ok && s.now().Sub(b.at) < MeshAgentCacheFor {
		return b.body, nil
	}
	body, err := s.fetchMeshAgent(ctx, arch)
	if errors.Is(err, meshcentral.ErrNoFile) {
		return nil, ErrMeshUnavailable
	}
	if err != nil {
		s.log.Error("agents: fetching MeshAgent from MeshCentral failed", "error", err, "arch", arch)
		return nil, ErrMeshUnavailable
	}
	if s.meshBins.bins == nil {
		s.meshBins.bins = map[int]meshBinary{}
	}
	s.meshBins.bins[arch] = meshBinary{body: body, at: s.now()}
	return body, nil
}

func (s *Service) fetchMeshAgent(ctx context.Context, arch int) ([]byte, error) {
	dl, err := s.mesh.Binary(ctx, arch)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dl.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(dl.Body, agentproto.MaxMeshAgentBytes+1))
	switch {
	case err != nil:
		return nil, err
	case len(body) > agentproto.MaxMeshAgentBytes:
		return nil, fmt.Errorf("MeshCentral's MeshAgent is larger than %d bytes", agentproto.MaxMeshAgentBytes)
	case dl.Length >= 0 && int64(len(body)) != dl.Length:
		return nil, fmt.Errorf("got %d of %d bytes", len(body), dl.Length)
	}
	return body, nil
}

// MeshAgentSettings returns the settings that join MeshAgent to the
// device's site.
func (s *Service) MeshAgentSettings(ctx context.Context, d *Device) ([]byte, error) {
	if s.mesh == nil {
		return nil, ErrMeshUnavailable
	}
	group, err := s.mesh.Group(ctx, d.SiteID)
	if err != nil {
		return nil, err
	}
	if group == "" {
		return nil, ErrMeshUnavailable
	}
	b, err := s.mesh.Settings(ctx, group)
	if err != nil {
		s.log.Error("agents: fetching MeshAgent settings from MeshCentral failed", "error", err, "site_id", d.SiteID)
		return nil, ErrMeshUnavailable
	}
	return b, nil
}

// SignDownload signs a download the agent will run (MeshAgent and its
// settings) with the job key it pinned, back to the verified request p for
// target (agentproto.SignDownload). Without the key it signs nothing, and
// agents refuse the download.
func (s *Service) SignDownload(p *SignedRequest, target string, body []byte) string {
	if s.updateKey == nil {
		return ""
	}
	return agentproto.SignDownload(s.updateKey, p.auth, target, sha256.Sum256(body))
}

// ChannelSettings is what a settings push carries for a device (ADR-0059):
// the heartbeat answer's interval and MeshAgent fields, read the way a
// heartbeat reads them but without the agent's report, so it settles
// nothing: the hash of the settings the device must apply after a move,
// until a heartbeat says it did. It is nil when the device is gone.
func (s *Service) ChannelSettings(ctx context.Context, id uuid.UUID) (*agentproto.ChannelSettings, error) {
	d := &Device{ID: id}
	var pending bool
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id, mesh_settings_pending FROM devices WHERE id = $1`, id).
			Scan(&d.OrganizationID, &d.SiteID, &pending)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("agents: reading a device's settings: %w", err)
	}
	out := &agentproto.ChannelSettings{HeartbeatSeconds: int(HeartbeatInterval.Seconds())}
	available, err := s.meshAvailable(ctx, d.SiteID)
	if err != nil {
		s.log.Warn("agents: checking remote access failed", "error", err, "device_id", id)
	}
	out.MeshAgent.Available = available
	if available && pending {
		if b, err := s.MeshAgentSettings(ctx, d); err == nil {
			sum := sha256.Sum256(b)
			out.MeshAgent.SettingsSHA256 = hex.EncodeToString(sum[:])
		}
	}
	return out, nil
}
