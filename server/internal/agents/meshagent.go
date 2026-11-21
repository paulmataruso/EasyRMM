package agents

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
)

// MeshAgentCacheFor is how long the server keeps a MeshAgent binary it
// fetched from MeshCentral. It must hold the whole binary to sign it before
// sending it, and a fleet installing at once then costs MeshCentral one
// download per platform.
const MeshAgentCacheFor = 10 * time.Minute

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
