package remote

import (
	"context"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
)

// MeshAgents delivers MeshAgent to enrolled devices (ADR-0015): the binary
// and the settings of the device's site group, downloaded from MeshCentral
// as the service account.
type MeshAgents struct {
	svc   *Service
	files *meshcentral.Files
}

// NewMeshAgents returns the MeshAgent source for the agent service.
func NewMeshAgents(svc *Service, files *meshcentral.Files) *MeshAgents {
	return &MeshAgents{svc: svc, files: files}
}

// Group returns the MeshCentral device group of a site, or "" when it has
// none yet.
func (m *MeshAgents) Group(ctx context.Context, siteID uuid.UUID) (string, error) {
	return m.svc.meshOf(ctx, siteID)
}

// Binary opens the MeshAgent for a MeshCentral architecture number.
func (m *MeshAgents) Binary(ctx context.Context, arch int) (*meshcentral.Download, error) {
	return m.files.Agent(ctx, arch)
}

// Settings returns the settings that join a device group.
func (m *MeshAgents) Settings(ctx context.Context, meshID string) ([]byte, error) {
	return m.files.Settings(ctx, meshID)
}

// Linked asks for a device refresh, so a newly linked MeshAgent shows its
// connection state without waiting for the periodic sync.
func (m *MeshAgents) Linked() { m.svc.DevicesChanged() }
