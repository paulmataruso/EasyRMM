package jobs

import (
	"slices"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/eventrules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// KindRegistryQuery and KindRegistryChange are the registry editor's kinds
// (ADR-0067): reads, and changes. Two, because retention, readers, the
// change lock and the record differ between them.
const (
	KindRegistryQuery  = "registry_query"
	KindRegistryChange = "registry_change"
)

// KindFilterRegistry is the Jobs list's filter for both registry kinds.
const KindFilterRegistry = "registry"

// KindEventlogQuery is the event viewer's kind (ADR-0068): reads of a Windows
// computer's event logs. Its filter in the Jobs list has the same name
// without the suffix.
const (
	KindEventlogQuery  = "eventlog_query"
	KindFilterEventlog = "eventlog"
)

// Executors of a kind.
const (
	ExecScript  = "script"
	ExecBuiltin = "builtin"
)

// Kind is one kind of job and everything that differs between kinds
// (ADR-0067, F2: kinds with an input and a result). The table below is the
// one place the server reads them from. A zero retention means the
// configured one: EASYRMM_JOB_OUTPUT_RETENTION for what a run keeps,
// EASYRMM_JOB_RETENTION for the job and its runs.
type Kind struct {
	Name string
	// Executor is ExecScript, a script the server sends, or ExecBuiltin,
	// Go code in the agent.
	Executor string
	Builtin  string
	// Platforms the kind runs on.
	Platforms []string
	// Requires are the capabilities the agent must list in its poll's
	// accepts, besides one input version of a builtin (BuiltinVersions).
	Requires []string
	// BuiltinVersions are the input versions the server writes, highest
	// first: the job needs the agent to list one of them.
	BuiltinVersions []int
	// ReadPerm is the kind's own permission for reading its input and result,
	// beside job.view_sensitive; empty for kinds without one. AskerOnly says
	// only the person who asked may read them.
	ReadPerm  rbac.Permission
	AskerOnly bool
	// KeepResult is how long the input and result are kept, counted from
	// when the job's last run ended; KeepJob how long the job and runs are.
	KeepResult, KeepJob time.Duration
	// WaitDefault and WaitMax are how long a run waits for an offline
	// device. A kind that waits for hours uses the job's own wait.
	WaitDefault, WaitMax time.Duration
	// Timeout is the run's timeout; Quick puts it in the reserved lane.
	Timeout time.Duration
	Quick   bool
	// Listed says the Jobs list shows the kind without a filter.
	Listed bool
	// AuditAction is the record `create` writes per run.
	AuditAction string
	// RecordRead is the record written when a result is read; empty when
	// the asker's own read is not recorded.
	RecordRead string
	// ChangeLock says the kind takes the device's change lock.
	ChangeLock bool
}

// Kinds is the table of kinds, by name.
var Kinds = map[string]Kind{
	KindScript:   {Name: KindScript, Executor: ExecScript, Listed: true, AuditAction: "device.script_run"},
	KindSoftware: {Name: KindSoftware, Executor: ExecScript, Listed: true, AuditAction: "device.software_action"},
	KindHardening: {Name: KindHardening, Executor: ExecScript, Listed: true, AuditAction: "device.hardening",
		ChangeLock: true},
	KindWinmod: {Name: KindWinmod, Executor: ExecScript, AuditAction: "winmod"},
	KindRegistryQuery: {
		Name: KindRegistryQuery, Executor: ExecBuiltin, Builtin: agentproto.BuiltinRegistry, Platforms: []string{"windows"},
		Requires: []string{agentproto.CapJobStructured}, BuiltinVersions: []int{agentproto.RegistryInputVersion},
		ReadPerm: rbac.PermRegistryView, AskerOnly: true,
		KeepResult: time.Hour, KeepJob: 7 * 24 * time.Hour,
		WaitDefault: 2 * time.Minute, WaitMax: 2 * time.Minute,
		Timeout: agentproto.QuickSeconds * time.Second, Quick: true,
		AuditAction: "registry.read",
	},
	KindEventlogQuery: {
		Name: KindEventlogQuery, Executor: ExecBuiltin, Builtin: agentproto.BuiltinEventlog, Platforms: []string{"windows"},
		Requires: []string{agentproto.CapJobStructured}, BuiltinVersions: []int{eventrules.InputVersion},
		ReadPerm: rbac.PermEventlogView, AskerOnly: true,
		KeepResult: time.Hour, KeepJob: 7 * 24 * time.Hour,
		WaitDefault: 2 * time.Minute, WaitMax: 2 * time.Minute,
		Timeout: agentproto.QuickSeconds * time.Second, Quick: true,
		AuditAction: "eventlog.query",
	},
	KindRegistryChange: {
		Name: KindRegistryChange, Executor: ExecBuiltin, Builtin: agentproto.BuiltinRegistry, Platforms: []string{"windows"},
		Requires: []string{agentproto.CapJobStructured}, BuiltinVersions: []int{agentproto.RegistryInputVersion},
		ReadPerm: rbac.PermRegistryView, RecordRead: "registry.change_view",
		WaitDefault: 15 * time.Minute, WaitMax: 7 * 24 * time.Hour,
		Timeout: agentproto.QuickSeconds * time.Second, Quick: true,
		AuditAction: "registry.change", ChangeLock: true,
	},
}

// builtinKinds lists the kinds that run a builtin, in a stable order.
func builtinKinds() []Kind {
	var out []Kind
	for _, k := range Kinds {
		if k.Executor == ExecBuiltin {
			out = append(out, k)
		}
	}
	slices.SortFunc(out, func(a, b Kind) int {
		if a.Name < b.Name {
			return -1
		}
		return 1
	})
	return out
}

// isStructured reports whether a kind runs a builtin with an input.
func isStructured(kind string) bool { return Kinds[kind].Executor == ExecBuiltin }

// needs lists what the agent must accept to be sent a job of the kind:
// its capabilities and the first input version of its builtin.
func (k Kind) needs() []string {
	out := slices.Clone(k.Requires)
	if k.Builtin != "" && len(k.BuiltinVersions) > 0 {
		out = append(out, agentproto.CapBuiltin(k.Builtin, k.BuiltinVersions[0]))
	}
	return out
}

// keepResult is how long the kind's input and results are kept after its
// last run ended.
func (k Kind) keepResult(s *Service) time.Duration {
	if k.KeepResult > 0 {
		return k.KeepResult
	}
	return s.outputRetention
}

// keepJob is how long the kind's jobs and runs are kept.
func (k Kind) keepJob(s *Service) time.Duration {
	if k.KeepJob > 0 {
		return k.KeepJob
	}
	return s.retention
}
