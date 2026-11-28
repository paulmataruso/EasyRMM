// Package posture reads a computer's security posture (ADR-0082). Posture is
// a view over three sources that already exist: Linux hardening (ADR-0051),
// Windows hardening (ADR-0054) and the patching engine. It collects nothing
// and keeps no result of its own. Each source's state is read as a result of
// the compliance engine's vocabulary (compliance.State*) and weighed by the
// compliance engine's roll-up (rollup.ScoreOf), so a computer's posture and a
// computer's compliance results use one set of words and one score.
//
// The wording is "meets its security policy". It never says "compliant".
package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/rollup"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// DefaultFreshDays is the freshness window of an organization that has not
// set one in the compliance settings (ADR-0078, section 4).
const DefaultFreshDays = 30

// Words are the three things posture says about a computer.
const (
	WordMeets       = compliance.WordMeets
	WordDoesNotMeet = compliance.WordDoesNotMeet
	WordCannotTell  = compliance.WordCannotTell
)

// Phrase is the word in a sentence about the computer.
func Phrase(word string) string {
	switch word {
	case WordMeets:
		return "Meets its security policy"
	case WordDoesNotMeet:
		return "Does not meet its security policy"
	}
	return "Cannot tell whether it meets its security policy"
}

// Ref is a computer posture is read for.
type Ref struct {
	ID       uuid.UUID
	Org      uuid.UUID
	Platform string
	// Enrolled says the computer has the EasyRMM agent, which hardening needs.
	Enrolled bool
}

// Posture is a computer's posture.
type Posture struct {
	rollup.Score
	// CheckedAt is the newest of the results it rests on; nil when none.
	CheckedAt *time.Time `json:"checkedAt"`
}

// Summary is the part of a posture the Devices list shows.
type Summary struct {
	Word       string     `json:"word"`
	Percent    *int       `json:"percent"`
	Failing    int        `json:"failing"`
	CannotTell int        `json:"cannotTell"`
	CheckedAt  *time.Time `json:"checkedAt"`
}

// Summary is the posture without its reasons.
func (p *Posture) Summary() *Summary {
	return &Summary{Word: p.Word, Percent: p.Percent, Failing: p.Failing, CannotTell: p.CannotTell, CheckedAt: p.CheckedAt}
}

// Filters of a device list or report (Query values).
const (
	FilterMeets       = "meets"
	FilterDoesNotMeet = "does_not_meet"
	FilterCannotTell  = "cannot_tell"
)

// ValidFilter says whether f is "" or a filter.
func ValidFilter(f string) bool {
	return f == "" || f == FilterMeets || f == FilterDoesNotMeet || f == FilterCannotTell
}

// Matches says whether a computer's posture passes a filter. A computer posture
// does not cover (no hardening on its platform, not enrolled) matches none.
func Matches(p *Posture, f string) bool {
	if f == "" {
		return true
	}
	if p == nil {
		return false
	}
	switch f {
	case FilterMeets:
		return p.Word == WordMeets
	case FilterDoesNotMeet:
		return p.Word == WordDoesNotMeet
	}
	return p.Word == WordCannotTell
}

// weights of the controls that matter most; every other control weighs 1.
// They are the default policy; an organization's posture policies (policy.go)
// replace them control by control.
var weights = map[string]int{
	"patching": 3, "firewall": 3, "ssh": 3, "defender": 3, "bitlocker": 3,
	DiskEncryption: 3, DefenderHealth: 3,
	"log-collection": 2, "accounts": 2, "uac": 2, "smb": 2, "lsa-protection": 2, "asr": 2, "audit": 2, "rdp": 2, "integrity": 2, "mac": 2,
}

// LogCollection is the control of a computer's log collection (slice P5).
const LogCollection = "log-collection"

// Log collection is read from when the computer last had log blocks accepted.
// Inside LogsFresh it is in place; past it, up to LogsSilent, collection is set
// up but not arriving (partly); past that, or never, it is not in place.
const (
	LogsFresh  = 24 * time.Hour
	LogsSilent = 7 * 24 * time.Hour
)

// logCollectionState says what the last accepted log blocks mean at now.
func logCollectionState(last *time.Time, now time.Time) (state, detail string) {
	if last == nil {
		return compliance.StateNotInPlace, "No collected logs have ever been received from this computer."
	}
	age := now.Sub(*last)
	switch {
	case age <= LogsFresh:
		return compliance.StateInPlace, ""
	case age <= LogsSilent:
		return compliance.StatePartly, "Log collection was set up but no logs have arrived for over a day."
	}
	return compliance.StateNotInPlace, "No logs have arrived for over a week."
}

// volumeKind is the kind of encrypted volume a platform reports.
func volumeKind(platform string) string {
	if platform == "windows" {
		return "bitlocker"
	}
	return "luks"
}

// notChecked is the one control of a computer no hardening job has reported on.
const notChecked = "hardening"

// covered says posture reads this computer: it runs hardening's script.
func covered(r Ref) bool { return r.Enrolled && (r.Platform == "linux" || r.Platform == "windows") }

// Label names a control for people.
func Label(id string) string {
	switch id {
	case "patching":
		return "Patching"
	case notChecked:
		return "Hardening"
	case "ssh":
		return "SSH"
	case "smb":
		return "SMB"
	case "uac":
		return "UAC"
	case "rdp":
		return "Remote Desktop"
	case "asr":
		return "Attack surface reduction"
	case "laps":
		return "LAPS"
	case "tls":
		return "TLS"
	case "ntlm":
		return "NTLM"
	case "wdigest":
		return "WDigest"
	case "bitlocker":
		return "BitLocker"
	case "fail2ban":
		return "fail2ban"
	case "luks":
		return "Disk encryption (LUKS)"
	case "host-firewall":
		return "Host firewall"
	case "selinux-apparmor":
		return "SELinux or AppArmor"
	case "auto-updates":
		return "Automatic updates"
	case LogCollection:
		return "Log collection"
	case DiskEncryption:
		return "Disk encryption state"
	case DefenderHealth:
		return "Defender health"
	}
	s := strings.ReplaceAll(id, "-", " ")
	if s == "" {
		return id
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

type moduleRow struct {
	state   string
	checked time.Time
	extra   []byte
}

type extra struct {
	Reason  string `json:"reason"`
	Missing string `json:"missing"`
	Managed []struct {
		Owner string `json:"owner"`
		State string `json:"state"`
	} `json:"managed"`
}

// patchState reads the patching engine's compliance word as a state of the
// shared vocabulary, with what to say about it.
func patchState(status string) (state, detail string) {
	switch status {
	case "Compliant":
		return compliance.StateInPlace, ""
	case "RebootRequired":
		return compliance.StatePartly, "A restart is needed to finish updates."
	case "MissingUpdates":
		return compliance.StateNotInPlace, "Updates are missing."
	case "FailedUpdates":
		return compliance.StateFailed, "Updates failed to install."
	case "ScanStale":
		return compliance.StateUnknown, "The patching scan is out of date."
	case "NeverScanned":
		return compliance.StateUnknown, "The patching engine has not scanned it."
	}
	return compliance.StateUnknown, "The patching engine gave no usable answer."
}

// Load reads the posture of the computers, in the caller's transaction. A
// computer outside devscope, or one posture does not cover, has no entry.
func Load(ctx context.Context, tx pgx.Tx, refs []Ref, now time.Time) (map[uuid.UUID]*Posture, error) {
	out := map[uuid.UUID]*Posture{}
	var ids []uuid.UUID
	orgs := map[uuid.UUID]time.Duration{}
	byID := map[uuid.UUID]Ref{}
	for _, r := range refs {
		if !covered(r) || !devscope.Allowed(r.Org) {
			continue
		}
		ids = append(ids, r.ID)
		byID[r.ID] = r
		orgs[r.Org] = DefaultFreshDays * 24 * time.Hour
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT organization_id, freshness_days FROM compliance_org_settings WHERE organization_id = ANY ($1)`, keys(orgs))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var o uuid.UUID
		var days int
		if err := rows.Scan(&o, &days); err != nil {
			rows.Close()
			return nil, err
		}
		orgs[o] = time.Duration(days) * 24 * time.Hour
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	overrides, err := loadOverrides(ctx, tx, keys(orgs))
	if err != nil {
		return nil, err
	}

	mods := map[uuid.UUID]map[string]moduleRow{}
	rows, err = tx.Query(ctx, `SELECT device_id, module, state, checked_at,
			jsonb_build_object('reason', detail->'reason', 'missing', detail->'missing'->0, 'managed', detail->'managed')
		FROM device_hardening WHERE device_id = ANY ($1)`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d uuid.UUID
		var module string
		var m moduleRow
		if err := rows.Scan(&d, &module, &m.state, &m.checked, &m.extra); err != nil {
			rows.Close()
			return nil, err
		}
		if mods[d] == nil {
			mods[d] = map[string]moduleRow{}
		}
		mods[d][module] = m
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	type patch struct {
		status  *string
		checked *time.Time
	}
	patches := map[uuid.UUID]patch{}
	rows, err = tx.Query(ctx, `SELECT e.device_id, p.status, p.checked_at FROM easypatch_devices e
		LEFT JOIN posture_patching p ON p.device_id = e.device_id WHERE e.state = 'linked' AND e.device_id = ANY ($1)`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d uuid.UUID
		var p patch
		if err := rows.Scan(&d, &p.status, &p.checked); err != nil {
			rows.Close()
			return nil, err
		}
		patches[d] = p
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	logs := map[uuid.UUID]time.Time{}
	rows, err = tx.Query(ctx, `SELECT device_id, last_received_at FROM posture_log_collection WHERE device_id = ANY ($1)`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d uuid.UUID
		var t time.Time
		if err := rows.Scan(&d, &t); err != nil {
			rows.Close()
			return nil, err
		}
		logs[d] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Slices P2 and P3: what the agent reported about volumes, and Defender's
	// status snapshot. Both are reads of rows that exist already, of the
	// computers the dev-scope guard allowed above.
	volReported := map[uuid.UUID]map[string]time.Time{}
	rows, err = tx.Query(ctx, `SELECT device_id, kind, reported_at FROM device_volume_reports WHERE device_id = ANY ($1)`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d uuid.UUID
		var kind string
		var t time.Time
		if err := rows.Scan(&d, &kind, &t); err != nil {
			rows.Close()
			return nil, err
		}
		if volReported[d] == nil {
			volReported[d] = map[string]time.Time{}
		}
		volReported[d][kind] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	vols := map[uuid.UUID][]Volume{}
	rows, err = tx.Query(ctx, `SELECT device_id, kind, mount, status FROM device_encrypted_volumes WHERE device_id = ANY ($1)`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d uuid.UUID
		var kind string
		var v Volume
		if err := rows.Scan(&d, &kind, &v.Mount, &v.Status); err != nil {
			rows.Close()
			return nil, err
		}
		if kind == volumeKind(byID[d].Platform) {
			vols[d] = append(vols[d], v)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	type snap struct {
		data  []byte
		taken time.Time
	}
	snaps := map[uuid.UUID]snap{}
	rows, err = tx.Query(ctx, `SELECT device_id, data, taken_at FROM windows_module_snapshots
		WHERE action = 'defender.status' AND params_hash = '' AND device_id = ANY ($1)`, ids)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d uuid.UUID
		var sn snap
		if err := rows.Scan(&d, &sn.data, &sn.taken); err != nil {
			rows.Close()
			return nil, err
		}
		snaps[d] = sn
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, id := range ids {
		r := byID[id]
		var items []rollup.Item
		var newest time.Time
		see := func(t time.Time) {
			if t.After(newest) {
				newest = t
			}
		}
		if len(mods[id]) == 0 {
			items = append(items, rollup.Item{ID: notChecked, Label: Label(notChecked), Weight: 3,
				Result: rollup.Result{State: compliance.StateUnknown}, Detail: "Hardening has not been checked on this computer."})
		}
		for module, m := range mods[id] {
			it := rollup.Item{ID: module, Label: Label(module), Weight: weights[module],
				Result: rollup.Result{State: m.state, CheckedAt: m.checked}}
			var x extra
			_ = json.Unmarshal(m.extra, &x) // a detail we cannot read gives no words, never a different state
			switch {
			case x.Reason != "":
				it.Detail = x.Reason
			case x.Missing != "":
				it.Detail = "Missing: " + x.Missing
			}
			if m.state == compliance.StateManagedElsewhere && len(x.Managed) > 0 {
				all := true
				for _, mg := range x.Managed {
					all = all && mg.State == compliance.StateInPlace
				}
				it.Result.Owner = &rollup.Owner{Name: x.Managed[0].Owner, Meets: &all}
				it.Detail = "Managed by " + x.Managed[0].Owner + "."
			}
			see(m.checked)
			items = append(items, it)
		}
		if p, ok := patches[id]; ok {
			it := rollup.Item{ID: "patching", Label: Label("patching"), Weight: weights["patching"], Result: rollup.Result{State: compliance.StateUnknown},
				Detail: "The patching engine has not been read yet."}
			if p.status != nil && p.checked != nil {
				st, detail := patchState(*p.status)
				it.Result = rollup.Result{State: st, CheckedAt: *p.checked}
				it.Detail = detail
				see(*p.checked)
			}
			items = append(items, it)
		}
		var lastLog *time.Time
		if t, ok := logs[id]; ok {
			lastLog = &t
		}
		lst, ldetail := logCollectionState(lastLog, now)
		lit := rollup.Item{ID: LogCollection, Label: Label(LogCollection), Weight: weights[LogCollection],
			Result: rollup.Result{State: lst}, Detail: ldetail}
		if lastLog != nil {
			lit.Result.CheckedAt = *lastLog
			see(*lastLog)
		}
		items = append(items, lit)
		eit := rollup.Item{ID: DiskEncryption, Label: Label(DiskEncryption), Weight: weights[DiskEncryption]}
		var reported *time.Time
		if t, ok := volReported[id][volumeKind(r.Platform)]; ok {
			reported = &t
			eit.Result.CheckedAt = t
			see(t)
		}
		est, edetail := encryptionState(r.Platform, reported, vols[id])
		eit.Result.State, eit.Detail = est, edetail
		items = append(items, eit)
		// Defender exists on Windows; with no snapshot (the module is off, so none
		// is read) the control is not there, as patching is not for an unlinked computer.
		if sn, ok := snaps[id]; ok && r.Platform == "windows" {
			dst, ddetail := defenderState(sn.data)
			items = append(items, rollup.Item{ID: DefenderHealth, Label: Label(DefenderHealth), Weight: weights[DefenderHealth],
				Result: rollup.Result{State: dst, CheckedAt: sn.taken}, Detail: ddetail})
			see(sn.taken)
		}
		items = applyOverrides(items, overrides[r.Org])
		po := &Posture{Score: rollup.ScoreOf(items, now, orgs[r.Org])}
		if !newest.IsZero() {
			t := newest
			po.CheckedAt = &t
		}
		out[id] = po
	}
	return out, nil
}

func keys(m map[uuid.UUID]time.Duration) []uuid.UUID {
	l := make([]uuid.UUID, 0, len(m))
	for k := range m {
		l = append(l, k)
	}
	return l
}

// ReasonText is a reason in one line, for a report's cell.
func ReasonText(r rollup.Reason) string {
	s := fmt.Sprintf("%s: %s", r.Label, r.Word)
	if r.State == compliance.StateStale {
		s += " (stale)"
	}
	if r.Detail != "" {
		s += " - " + strings.TrimSuffix(r.Detail, ".")
	}
	return s
}
