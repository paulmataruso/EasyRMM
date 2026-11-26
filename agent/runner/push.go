package runner

import (
	"context"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// ApplyRepair carries out a repair step the server pushed over the channel
// (ADR-0059): the code that does it for a heartbeat answer, and a heartbeat
// to report the outcome once it is done.
func (r *Runner) ApplyRepair(ctx context.Context, s *agentproto.SignedRepair) {
	r.startRepair(ctx, s)
}

// ApplySettings takes the settings the server pushed: MeshAgent's new
// settings, when the hash names ones this agent has not applied, and then a
// heartbeat, whose answer carries the interval and tells the server what was
// applied.
func (r *Runner) ApplySettings(ctx context.Context, s agentproto.ChannelSettings) {
	if r.Mesh != nil && r.Mesh.Installed() {
		if want := s.MeshAgent.SettingsSHA256; want != "" && want != r.Mesh.AppliedSettings() {
			if err := r.applyMeshSettings(ctx, want); err != nil {
				r.Log.Error("applying MeshAgent's new settings failed", "error", err)
			} else {
				r.Log.Info("MeshAgent joined its device group again after the device moved")
			}
		}
	}
	if r.Nudge != nil {
		r.Nudge("settings")
	}
}
