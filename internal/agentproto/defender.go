package agentproto

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// What the agent reports of Microsoft Defender and of the files it
// installs (ADR-0070).

// DefenderPolicy is the server's answer to whether an agent may act on
// Defender and hash what is installed. The server decides, per device;
// the agent does nothing on a device it did not allow.
type DefenderPolicy struct {
	Enabled bool `json:"enabled"`
}

// States of a device's exclusions, as a whole and per kind.
const (
	DefenderEffective        = "effective"
	DefenderNotEffective     = "present_not_effective"
	DefenderNotLocked        = "not_locked"
	DefenderRefused          = "refused"
	DefenderUnavailable      = "unavailable"
	DefenderNotApplicable    = "not_applicable"
	DefenderNotNeeded        = "not_needed"
	DefenderKindPath         = "path"
	DefenderKindProcess      = "process"
	DefenderKindASR          = "asr"
	DefenderKindControlledFA = "cfa"
	MaxDefenderFolders       = 16
	MaxDefenderEvents        = 32
	MaxDefenderText          = 300
	MaxInstalledFiles        = 64
	MaxInstalledName         = 260
	MaxInstalledBytes        = 24 << 10
	InstalledAgent           = "easyrmm-agent"
	InstalledMeshAgent       = "meshagent"
	InstalledPatchAgent      = "easypatch-agent"
	DefenderEventAdd         = "add"
	DefenderEventRemove      = "remove"
	DefenderEventLock        = "lock"
	DefenderEventNotLocked   = "not_locked"
	DefenderEventRefuse      = "refuse"
	defenderEventAuditPrefix = "device.defender_exclusion."
)

// DefenderAuditAction is the audit action of a reported event.
func DefenderAuditAction(kind string) string { return defenderEventAuditPrefix + kind }

// DefenderKinds are the four kinds of exclusion, in the order they are
// shown.
var DefenderKinds = []string{DefenderKindPath, DefenderKindProcess, DefenderKindASR, DefenderKindControlledFA}

// DefenderFolder is one folder the agent works out of.
type DefenderFolder struct {
	Path string `json:"path"`
	// Listed: the exact path is in Defender's ExclusionPath.
	Listed bool `json:"listed"`
	// Ours: the agent's record says it added it.
	Ours bool `json:"ours"`
	// Reason is why the folder was not locked down; empty when it was.
	Reason string `json:"reason,omitempty"`
}

// DefenderKind is the state of one kind of exclusion.
type DefenderKind struct {
	Kind   string `json:"kind"`
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// DefenderEvent is something the agent did to the exclusions or a folder,
// which the server writes into its audit chain.
type DefenderEvent struct {
	// Kind is add, remove, lock, not_locked or refuse.
	Kind string `json:"kind"`
	// ExclusionKind is path, process, asr or cfa; empty for lock events.
	ExclusionKind string    `json:"exclusionKind,omitempty"`
	Path          string    `json:"path"`
	Reason        string    `json:"reason,omitempty"`
	At            time.Time `json:"at"`
}

// DefenderReport is the state of Defender's exclusions on a device.
type DefenderReport struct {
	State   string           `json:"state"`
	Reason  string           `json:"reason,omitempty"`
	Kinds   []DefenderKind   `json:"kinds"`
	Folders []DefenderFolder `json:"folders"`
	// Method is "powershell" or "wmi": which one the last call used.
	Method string `json:"method,omitempty"`
	// AgentVersion is the agent that wrote the report.
	AgentVersion string `json:"agentVersion,omitempty"`
	// Events are what happened since the last report the server took.
	Events []DefenderEvent `json:"events,omitempty"`
	// EasyPatch is the EasyPatch agent's own report (its `defender status`),
	// which the EasyRMM agent forwards (ADR-0070 slice B). It holds no
	// report of its own and no events.
	EasyPatch *DefenderReport `json:"easypatch,omitempty"`
}

// InstalledFile is the hash of one program file on the device.
type InstalledFile struct {
	// Program is easyrmm-agent, meshagent or easypatch-agent.
	Program string `json:"program"`
	// Name is the file's name, without its folder.
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	MD5    string `json:"md5"`
	SHA256 string `json:"sha256"`
}

// InstalledFiles are the hashes of the agents' program files, with the
// versions of the programs they belong to.
type InstalledFiles struct {
	Files []InstalledFile `json:"files"`
	// AgentVersion is the EasyRMM agent's; MeshAgentVersion is MeshAgent's
	// (a hash alone does not say which build it is); PatchAgentVersion is
	// the EasyPatch agent's, when installed.
	AgentVersion      string    `json:"agentVersion"`
	MeshAgentVersion  string    `json:"meshAgentVersion,omitempty"`
	PatchAgentVersion string    `json:"patchAgentVersion,omitempty"`
	ObservedAt        time.Time `json:"observedAt"`
}

var defenderStates = map[string]bool{
	DefenderEffective: true, DefenderNotEffective: true, DefenderNotLocked: true, DefenderRefused: true,
	DefenderUnavailable: true, DefenderNotApplicable: true, DefenderNotNeeded: true,
}

// Check validates a report as the server stores it: known states, bounded
// lists and text.
func (r *DefenderReport) Check() error {
	if r.EasyPatch != nil {
		if r.EasyPatch.EasyPatch != nil || len(r.EasyPatch.Events) > 0 {
			return errors.New("the EasyPatch Defender report holds a report or events")
		}
		if err := r.EasyPatch.Check(); err != nil {
			return fmt.Errorf("the EasyPatch Defender report: %w", err)
		}
	}
	if !defenderStates[r.State] || r.State == DefenderNotNeeded {
		return fmt.Errorf("the Defender state %q is unknown", r.State)
	}
	if len(r.Kinds) > len(DefenderKinds) || len(r.Folders) > MaxDefenderFolders || len(r.Events) > MaxDefenderEvents {
		return errors.New("the Defender report has too many entries")
	}
	for _, k := range r.Kinds {
		if !defenderStates[k.State] || !validKind(k.Kind) || len(k.Reason) > MaxDefenderText {
			return errors.New("a Defender kind is not valid")
		}
	}
	for _, f := range r.Folders {
		if f.Path == "" || len(f.Path) > MaxInstalledName || len(f.Reason) > MaxDefenderText {
			return errors.New("a Defender folder is not valid")
		}
	}
	for _, e := range r.Events {
		switch e.Kind {
		case DefenderEventAdd, DefenderEventRemove, DefenderEventLock, DefenderEventNotLocked, DefenderEventRefuse:
		default:
			return fmt.Errorf("the Defender event %q is unknown", e.Kind)
		}
		if (e.ExclusionKind != "" && !validKind(e.ExclusionKind)) || len(e.Path) > MaxInstalledName || len(e.Reason) > MaxDefenderText {
			return errors.New("a Defender event is not valid")
		}
	}
	if len(r.Reason) > MaxDefenderText || len(r.Method) > 16 || len(r.AgentVersion) > 64 {
		return errors.New("the Defender report has text that is too long")
	}
	return nil
}

func validKind(k string) bool {
	for _, x := range DefenderKinds {
		if x == k {
			return true
		}
	}
	return false
}

func hexOf(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Check validates installed-file facts: at most MaxInstalledFiles files,
// names of at most MaxInstalledName characters, lowercase hex hashes, and
// a bounded whole.
func (f *InstalledFiles) Check() error {
	if len(f.Files) > MaxInstalledFiles {
		return fmt.Errorf("more than %d installed files", MaxInstalledFiles)
	}
	total := len(f.AgentVersion) + len(f.MeshAgentVersion) + len(f.PatchAgentVersion)
	for _, x := range f.Files {
		switch x.Program {
		case InstalledAgent, InstalledMeshAgent, InstalledPatchAgent:
		default:
			return fmt.Errorf("the program %q is unknown", x.Program)
		}
		if x.Name == "" || len(x.Name) > MaxInstalledName || strings.ContainsAny(x.Name, `/\`) {
			return errors.New("an installed file has a name that is not valid")
		}
		if !hexOf(x.MD5, 32) || !hexOf(x.SHA256, 64) || x.Size < 0 {
			return errors.New("an installed file has a hash that is not valid")
		}
		total += len(x.Program) + len(x.Name) + 120
	}
	if total > MaxInstalledBytes || len(f.AgentVersion) > 64 || len(f.MeshAgentVersion) > 64 || len(f.PatchAgentVersion) > 64 {
		return errors.New("the installed-file report is too large")
	}
	return nil
}
