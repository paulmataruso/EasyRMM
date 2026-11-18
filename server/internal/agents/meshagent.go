package agents

import (
	"context"
	"errors"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
)

// MeshAgentBinary opens the MeshAgent build for a platform (Go's GOOS and
// GOARCH names), from the MeshCentral this server runs.
func (s *Service) MeshAgentBinary(ctx context.Context, goos, goarch string) (*meshcentral.Download, error) {
	if s.mesh == nil {
		return nil, ErrMeshUnavailable
	}
	arch := agentproto.MeshArch(goos, goarch)
	if arch == 0 {
		return nil, apperr.Invalid("arch", "MeshAgent is not available for this platform.")
	}
	dl, err := s.mesh.Binary(ctx, arch)
	if errors.Is(err, meshcentral.ErrNoFile) {
		return nil, ErrMeshUnavailable
	}
	if err != nil {
		s.log.Error("agents: fetching MeshAgent from MeshCentral failed", "error", err, "arch", arch)
		return nil, ErrMeshUnavailable
	}
	return dl, nil
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
