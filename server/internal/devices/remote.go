package devices

import (
	"encoding/json"
	"time"
)

// Why a device's remote access is not connected (ADR-0069, "MeshAgent
// watchdog"), from what its EasyRMM agent reported about MeshAgent and what
// MeshCentral says.
const (
	// RemoteConnected: MeshCentral sees MeshAgent connected.
	RemoteConnected = "connected"
	// RemoteDeviceOffline: the EasyRMM agent is not checking in either, so
	// nothing is known about MeshAgent.
	RemoteDeviceOffline = "device_offline"
	// RemoteUnknown: the EasyRMM agent checks in but has not reported
	// MeshAgent's state (an older agent).
	RemoteUnknown = "unknown"
	// RemoteNotInstalled: MeshAgent's program or settings are missing.
	RemoteNotInstalled = "not_installed"
	// RemoteNotRunning: installed, but its service or process is not running.
	RemoteNotRunning = "not_running"
	// RemoteOtherServer: its settings name another MeshCentral server.
	RemoteOtherServer = "other_server"
	// RemoteOtherGroup: its node is in another site's MeshCentral group.
	RemoteOtherGroup = "other_group"
	// RemoteNotConnected: running, with the right settings, but MeshCentral
	// does not see it connected.
	RemoteNotConnected = "not_connected"
)

// RemoteStatus says whether a device's remote access is connected and, when
// it is not, why. Nil for a device without the EasyRMM agent, where
// MeshCentral's own view is all there is.
type RemoteStatus struct {
	// Reason is one of the Remote* constants.
	Reason string `json:"reason"`
	// Message says it in a sentence, without a time.
	Message string `json:"message"`
	// Since is when MeshCentral's view last changed, set for
	// RemoteNotConnected (and the reasons before it, which are the cause of
	// it).
	Since *time.Time `json:"since"`
	// Host is the MeshCentral host MeshAgent's settings name, when reported.
	Host string `json:"host,omitempty"`
	// Error is the last error MeshAgent had on the device, when reported.
	Error string `json:"error,omitempty"`
	// ReportedAt is when the EasyRMM agent last reported MeshAgent's state.
	ReportedAt *time.Time `json:"reportedAt"`
}

// meshState is what a heartbeat stored of MeshAgent's state
// (agents.MeshState).
type meshState struct {
	Installed bool   `json:"installed"`
	Running   bool   `json:"running"`
	Host      string `json:"host"`
	Error     string `json:"error"`
	HostOK    *bool  `json:"hostOk"`
}

// remoteInput is what RemoteReason decides from.
type remoteInput struct {
	remoteOnline, agentOnline, wrongGroup bool
	state                                 []byte // the stored JSON, nil when none
	stateAt, changedAt, enrolledAt        *time.Time
}

// RemoteReason returns the reason remote access is not connected, and its
// message: the first that applies. It is shared with the alerts, which show
// the same words.
func RemoteReason(connected, agentOnline, wrongGroup bool, stored []byte) (reason, message string) {
	r := remoteInput{remoteOnline: connected, agentOnline: agentOnline, wrongGroup: wrongGroup, state: stored}
	st := r.decide()
	return st.Reason, st.Message
}

func (r remoteInput) decide() RemoteStatus {
	var st meshState
	have := len(r.state) > 0 && json.Unmarshal(r.state, &st) == nil
	out := RemoteStatus{ReportedAt: r.stateAt}
	if have {
		out.Host, out.Error = st.Host, st.Error
	}
	switch {
	case r.remoteOnline:
		out.Reason, out.Message = RemoteConnected, "MeshAgent is connected to MeshCentral."
		return out
	case !r.agentOnline:
		out.Reason, out.Message = RemoteDeviceOffline, "The device is not checking in, so MeshAgent's state is not known."
		return out
	case !have:
		out.Reason, out.Message = RemoteUnknown, "MeshAgent is not connected to MeshCentral, and this agent does not report why. Updating the EasyRMM agent adds it."
		return out
	}
	switch {
	case !st.Installed:
		out.Reason, out.Message = RemoteNotInstalled, "MeshAgent is not installed on the device."
	case !st.Running:
		out.Reason, out.Message = RemoteNotRunning, "MeshAgent is installed but not running."
	case st.HostOK != nil && !*st.HostOK:
		out.Reason, out.Message = RemoteOtherServer, "MeshAgent's settings name another MeshCentral server."
	case r.wrongGroup:
		out.Reason, out.Message = RemoteOtherGroup, "MeshAgent's node is in another site's MeshCentral group."
	default:
		out.Reason, out.Message = RemoteNotConnected, "MeshAgent is running but is not connected to MeshCentral."
		out.Since = r.since()
	}
	return out
}

// since is when MeshCentral's view of the device last changed, or when it
// was enrolled before it changed at all.
func (r remoteInput) since() *time.Time {
	if r.changedAt != nil {
		return r.changedAt
	}
	return r.enrolledAt
}

// remoteStatus decides a device's remote status from its row.
func remoteStatus(r remoteInput) *RemoteStatus {
	st := r.decide()
	return &st
}

// LeavingSQL is a condition, over a devices row aliased d, that holds for a
// device that is leaving: its removal is asked for or its EasyPatch agent is
// being removed or opted out. Nothing repairs such a device and none of
// ADR-0069's alerts open for it ("Never for a device that is leaving").
const LeavingSQL = `(EXISTS (SELECT 1 FROM device_removals x WHERE x.device_id = d.id)
	OR EXISTS (SELECT 1 FROM easypatch_removals x WHERE x.device_id = d.id)
	OR EXISTS (SELECT 1 FROM easypatch_opt_outs x WHERE x.device_id = d.id))`
