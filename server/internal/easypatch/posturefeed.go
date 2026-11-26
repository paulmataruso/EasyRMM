package easypatch

import (
	"context"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/posture"
)

// PosturePatching is the patching engine as security posture reads it
// (ADR-0082): the compliance word of every linked device. The time is when the
// engine was read, so a feed that stops makes the copy go stale. A device whose
// organization the engine could not be read for is left out, and keeps its
// last copy.
func (s *Service) PosturePatching(ctx context.Context) ([]posture.PatchStatus, error) {
	fleet, err := s.Fleet(ctx, access.System("posture"), FleetQuery{})
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	out := make([]posture.PatchStatus, 0, len(fleet.Devices))
	for _, d := range fleet.Devices {
		if d.Endpoint == nil || d.Endpoint.ComplianceStatus == "" {
			continue
		}
		out = append(out, posture.PatchStatus{DeviceID: d.DeviceID, OrganizationID: d.OrganizationID, Status: d.Endpoint.ComplianceStatus, At: now})
	}
	return out, nil
}
