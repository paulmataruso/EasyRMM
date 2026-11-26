package defender

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// System is what the machine does to a folder: lock it down to SYSTEM and
// Administrators, and verify that it, what is above it and everything in it
// are administrators-only (ADR-0070, section 2).
type System interface {
	Lock(dir string) error
	Verify(dir string) error
}

// Manager keeps the exclusions of one agent.
type Manager struct {
	Backend Backend
	System  System
	// Folders are the working folders, excluded whole as paths and, with
	// the Attack Surface Reduction kind, as ASR exclusions.
	Folders []string
	// Programs are the full paths of the executables excluded as processes
	// and allowed through Controlled Folder Access. An executable is
	// excluded only when its own folder is one of Folders or inside one.
	Programs   []string
	RecordFile string
	Version    string
	Log        *slog.Logger
	Now        func() time.Time

	mu     sync.Mutex
	events []agentproto.DefenderEvent
	seen   map[string]string // folder state last logged, so a steady state logs once
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) emit(kind, ek, path, reason string) {
	m.Log.Info("Defender exclusions", "event", kind, "exclusion", ek, "path", path, "reason", reason, "version", m.Version)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) >= agentproto.MaxDefenderEvents {
		m.events = m.events[1:]
	}
	m.events = append(m.events, agentproto.DefenderEvent{Kind: kind, ExclusionKind: ek, Path: path, Reason: clip(reason), At: m.now()})
}

// TakeEvents returns the events since the last call.
func (m *Manager) TakeEvents() []agentproto.DefenderEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.events
	m.events = nil
	return e
}

// RestoreEvents puts events back at the front: the report that carried
// them did not reach the server.
func (m *Manager) RestoreEvents(e []agentproto.DefenderEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(slices.Clone(e), m.events...)
	if over := len(m.events) - agentproto.MaxDefenderEvents; over > 0 {
		m.events = m.events[over:]
	}
}

func clip(s string) string {
	if len(s) > agentproto.MaxDefenderText {
		return s[:agentproto.MaxDefenderText]
	}
	return s
}

func (m *Manager) loadRecord() Record {
	r, found, err := LoadRecord(m.RecordFile)
	if err != nil {
		m.Log.Warn("the Defender record cannot be read; treating no exclusion as the agent's own", "error", err, "found", found)
	}
	return r
}

type desired struct{ kind, path string }

// dirOf is the folder of a Windows path, whatever system the code runs on.
func dirOf(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[:i]
	}
	return "."
}

// inside reports whether p is dir or below it.
func inside(dir, p string) bool {
	d, q := Norm(dir), Norm(p)
	return q == d || strings.HasPrefix(q, d+`\`)
}

// Reconcile locks the folders down and verifies them, then adds the
// exclusions that are missing and removes the agent's own for a folder that
// no longer verifies. It never fails: what went wrong is in the report.
func (m *Manager) Reconcile(ctx context.Context) *agentproto.DefenderReport {
	rep := &agentproto.DefenderReport{AgentVersion: m.Version}
	locked := map[string]bool{}
	reasons := map[string]string{}
	for _, f := range m.Folders {
		if err := m.System.Lock(f); err != nil {
			reasons[f] = "could not be locked down: " + err.Error()
		} else if err := m.System.Verify(f); err != nil {
			reasons[f] = err.Error()
		} else {
			locked[f] = true
		}
		m.noteFolder(f, reasons[f])
	}
	rec := m.loadRecord()
	prefs, err := m.Backend.Read(ctx)
	rep.Method = m.Backend.Method()
	switch {
	case err != nil:
		rep.State, rep.Reason = agentproto.DefenderUnavailable, clip(err.Error())
	case prefs.Missing:
		rep.State, rep.Reason = agentproto.DefenderNotApplicable, "Microsoft Defender is not installed on this machine."
	case prefs.NA != "":
		rep.State, rep.Reason = agentproto.DefenderUnavailable, clip("Defender does not show its exclusions to the agent: "+prefs.NA)
	default:
		if why := inactive(prefs); why != "" {
			rep.State, rep.Reason = agentproto.DefenderNotApplicable, why
		}
	}
	if rep.State != "" {
		m.fill(rep, reasons, &rec, Prefs{})
		return rep
	}

	// Removed: the agent's own for a folder that no longer verifies.
	for _, f := range m.Folders {
		if locked[f] {
			continue
		}
		for _, kind := range []string{"path", "asr"} {
			if rec.Has(kind, f) {
				m.dropOwn(ctx, &rec, kind, f, reasons[f])
			}
		}
	}
	for _, exe := range m.Programs {
		if !m.programFolderLocked(exe, locked) {
			for _, kind := range []string{"process", "cfa"} {
				if rec.Has(kind, exe) {
					m.dropOwn(ctx, &rec, kind, exe, "its folder is not locked down")
				}
			}
		}
	}

	var want []desired
	for _, f := range m.Folders {
		if locked[f] {
			want = append(want, desired{"path", f}, desired{"asr", f})
		}
	}
	for _, exe := range m.Programs {
		if m.programFolderLocked(exe, locked) {
			want = append(want, desired{"process", exe}, desired{"cfa", exe})
		}
	}
	refused := map[string]string{}
	for _, w := range want {
		if listed(prefs.Lists[w.kind], w.path) {
			continue // already there: ours if recorded, an administrator's if not
		}
		err := m.Backend.Add(ctx, w.kind, w.path)
		var refusal *Refused
		switch {
		case err == nil:
			rec.Put(Entry{Kind: w.kind, Path: w.path, At: m.now(), AgentVersion: m.Version})
			if serr := rec.Save(m.RecordFile); serr != nil {
				m.Log.Error("writing the Defender record failed", "error", serr)
			}
			m.emit(agentproto.DefenderEventAdd, w.kind, w.path, "")
		case errors.As(err, &refusal):
			refused[w.kind] = refusal.Reason
			m.emit(agentproto.DefenderEventRefuse, w.kind, w.path, refusal.Reason)
		default:
			refused[w.kind] = "unavailable: " + err.Error()
			m.Log.Warn("adding a Defender exclusion failed", "exclusion", w.kind, "path", w.path, "error", err)
		}
	}
	rep.Method = m.Backend.Method()
	after, err := m.Backend.Read(ctx)
	if err != nil {
		rep.State, rep.Reason = agentproto.DefenderUnavailable, clip(err.Error())
		m.fill(rep, reasons, &rec, prefs)
		return rep
	}
	m.fill(rep, reasons, &rec, after)
	m.kinds(rep, want, refused, after)
	m.overall(rep, after, prefs)
	return rep
}

func (m *Manager) programFolderLocked(exe string, locked map[string]bool) bool {
	for f := range locked {
		if inside(f, dirOf(exe)) {
			return true
		}
	}
	return false
}

func (m *Manager) dropOwn(ctx context.Context, rec *Record, kind, path, why string) {
	if err := m.Backend.Remove(ctx, kind, path); err != nil {
		m.Log.Warn("removing a Defender exclusion failed", "exclusion", kind, "path", path, "error", err)
		return
	}
	rec.Drop(kind, path)
	if err := rec.Save(m.RecordFile); err != nil {
		m.Log.Error("writing the Defender record failed", "error", err)
	}
	m.emit(agentproto.DefenderEventRemove, kind, path, why)
}

func (m *Manager) noteFolder(f, reason string) {
	m.mu.Lock()
	if m.seen == nil {
		m.seen = map[string]string{}
	}
	prev, had := m.seen[f]
	m.seen[f] = reason
	m.mu.Unlock()
	switch {
	case reason != "" && (!had || prev != reason):
		m.emit(agentproto.DefenderEventNotLocked, "", f, reason)
	case reason == "" && (!had || prev != ""):
		m.emit(agentproto.DefenderEventLock, "", f, "")
	}
}

func listed(list []string, p string) bool {
	return slices.ContainsFunc(list, func(e string) bool { return same(e, p) })
}

// inactive says why Defender is not the active antivirus, or "" when it is.
func inactive(p Prefs) string {
	switch {
	case p.RunningMode != "" && !strings.EqualFold(p.RunningMode, "Normal"):
		return fmt.Sprintf("Microsoft Defender is not the active antivirus (running mode %s); another product is, or it is passive.", p.RunningMode)
	case !p.AntivirusOn || !p.ServiceOn:
		return "Microsoft Defender antivirus is turned off."
	case !p.RealTimeOn:
		return "Defender's real-time protection is off, so exclusions change nothing."
	}
	return ""
}

func (m *Manager) fill(rep *agentproto.DefenderReport, reasons map[string]string, rec *Record, p Prefs) {
	for _, f := range m.Folders {
		rep.Folders = append(rep.Folders, agentproto.DefenderFolder{
			Path: f, Listed: listed(p.Lists["path"], f), Ours: rec.Has("path", f), Reason: clip(reasons[f]),
		})
	}
	if rep.Kinds == nil {
		for _, k := range agentproto.DefenderKinds {
			rep.Kinds = append(rep.Kinds, agentproto.DefenderKind{Kind: k, State: rep.State, Reason: rep.Reason})
		}
	}
	rep.Events = m.TakeEvents()
}

func (m *Manager) kinds(rep *agentproto.DefenderReport, want []desired, refused map[string]string, after Prefs) {
	rep.Kinds = nil
	for _, k := range agentproto.DefenderKinds {
		kind := agentproto.DefenderKind{Kind: k, State: agentproto.DefenderEffective}
		missing := false
		for _, w := range want {
			if w.kind == k && !listed(after.Lists[k], w.path) {
				missing = true
			}
		}
		switch {
		case refused[k] != "" && strings.HasPrefix(refused[k], "unavailable: "):
			kind.State, kind.Reason = agentproto.DefenderUnavailable, strings.TrimPrefix(refused[k], "unavailable: ")
		case refused[k] != "":
			kind.State, kind.Reason = agentproto.DefenderRefused, refused[k]
			if after.TamperProtected {
				kind.Reason += " (Tamper Protection is on)"
			}
		case missing:
			kind.State, kind.Reason = agentproto.DefenderRefused, "Defender accepted the change but did not list it afterwards."
			if after.TamperProtected {
				kind.Reason += " Tamper Protection is on."
			}
		case k == "cfa" && !after.CFAOn:
			kind.State, kind.Reason = agentproto.DefenderNotNeeded, "Controlled Folder Access is off."
		case k == "asr" && after.ASRRules == 0:
			kind.State, kind.Reason = agentproto.DefenderNotNeeded, "No Attack Surface Reduction rule is set."
		}
		kind.Reason = clip(kind.Reason)
		rep.Kinds = append(rep.Kinds, kind)
	}
}

func (m *Manager) overall(rep *agentproto.DefenderReport, after, before Prefs) {
	rep.State = agentproto.DefenderEffective
	for _, f := range rep.Folders {
		if f.Reason != "" {
			rep.State, rep.Reason = agentproto.DefenderNotLocked, clip(f.Path+" "+strings.TrimPrefix(f.Reason, f.Path+" "))
			return
		}
	}
	for _, k := range rep.Kinds {
		if k.State == agentproto.DefenderRefused || k.State == agentproto.DefenderUnavailable {
			rep.State, rep.Reason = k.State, clip(k.Kind+": "+k.Reason)
			return
		}
	}
	// Read before the add, and after: a policy may set it at any time.
	if before.DisableLocalAdminMerge || after.DisableLocalAdminMerge {
		rep.State, rep.Reason = agentproto.DefenderNotEffective, "local exclusions are ignored (DisableLocalAdminMerge)"
	}
}

// Remove removes exactly the recorded exclusions, one call each. Without a
// usable record it removes only entries that exactly match the fixed set
// and only for folders that still verify. The entries that could not be
// removed are returned, and stay in the record.
func (m *Manager) Remove(ctx context.Context) (left Record, err error) {
	rec, found, rerr := LoadRecord(m.RecordFile)
	left = Record{Version: 1}
	if rerr != nil || !found {
		return m.removeFixed(ctx, found, rerr)
	}
	for _, e := range rec.Entries {
		if err := m.Backend.Remove(ctx, e.Kind, e.Path); err != nil {
			m.Log.Warn("removing a Defender exclusion failed; it stays in the record", "exclusion", e.Kind, "path", e.Path, "error", err)
			left.Entries = append(left.Entries, e)
			continue
		}
		m.emit(agentproto.DefenderEventRemove, e.Kind, e.Path, "the agent was uninstalled")
	}
	if len(left.Entries) == 0 {
		return left, removeFile(m.RecordFile)
	}
	return left, left.Save(m.RecordFile)
}

func (m *Manager) removeFixed(ctx context.Context, found bool, rerr error) (Record, error) {
	left := Record{Version: 1}
	why := "there is no record"
	if found {
		why = "the record cannot be read: " + rerr.Error()
	}
	prefs, err := m.Backend.Read(ctx)
	if err != nil || prefs.Missing || prefs.NA != "" {
		m.Log.Warn("Defender could not be read; no exclusion was removed", "why", why, "error", err)
		return left, nil
	}
	var set []desired
	for _, f := range m.Folders {
		if m.System.Verify(f) == nil {
			set = append(set, desired{"path", f}, desired{"asr", f})
		} else {
			m.Log.Info("an exclusion is left: its folder does not verify as administrators-only", "path", f)
		}
	}
	for _, exe := range m.Programs {
		if slices.ContainsFunc(m.Folders, func(f string) bool { return inside(f, dirOf(exe)) && m.System.Verify(f) == nil }) {
			set = append(set, desired{"process", exe}, desired{"cfa", exe})
		}
	}
	for _, w := range set {
		if !listed(prefs.Lists[w.kind], w.path) {
			continue
		}
		if err := m.Backend.Remove(ctx, w.kind, w.path); err != nil {
			m.Log.Warn("removing a Defender exclusion failed", "exclusion", w.kind, "path", w.path, "error", err)
			continue
		}
		m.emit(agentproto.DefenderEventRemove, w.kind, w.path, "the agent was uninstalled and "+why)
	}
	return left, removeFile(m.RecordFile)
}
