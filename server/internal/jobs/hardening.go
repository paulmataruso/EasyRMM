package jobs

import (
	"bytes"
	"context"
	_ "embed" // the hardening script
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Hardening Linux computers (ADR-0051): a job of EasyRMM's own script, with
// the mode, the modules and the options as arguments.

// KindHardening is the kind of a hardening job.
const KindHardening = "hardening"

// HardeningCheck is the mode that reports what is in place and what apply
// would change, and changes nothing.
const HardeningCheck = "check"

// HardeningTimeout is how long a hardening job may run (ADR-0051).
const HardeningTimeout = 30 * 60

// MaxJobBody is the largest script a job may carry: the jobs table's limit,
// above a library script's MaxBody, for EasyRMM's own scripts.
const MaxJobBody = 512 << 10

// HardeningResultPrefix starts the last line of a hardening job's output,
// the JSON result.
const HardeningResultPrefix = "EASYRMM-HARDENING-RESULT-V1 "

// maxHardeningResult bounds the result line.
const maxHardeningResult = 64 << 10

//go:embed hardening/linux.sh
var hardeningScript string

// HardeningModules are the modules, in the order the script runs them and
// the console lists them.
var HardeningModules = []string{
	"ssh", "firewall", "fail2ban", "kernel", "audit", "permissions", "services", "kernel-modules", "sudo", "time",
	"shared-memory", "usb-storage", "mac", "integrity",
}

// Hardening is what a hardening job does.
type Hardening struct {
	Mode    string           `json:"mode"`
	Modules []string         `json:"modules"`
	Options HardeningOptions `json:"options"`
}

// HardeningOptions change what a module does. Each applies to one module.
type HardeningOptions struct {
	// AllowTCP and AllowUDP are ports and ranges ("8080", "9000-9100") the
	// firewall leaves open besides those in use.
	AllowTCP []string `json:"allowTcp,omitempty"`
	AllowUDP []string `json:"allowUdp,omitempty"`
	// Trusted are addresses and ranges fail2ban never bans.
	Trusted []string `json:"trusted,omitempty"`
	// RootPasswordOff turns root's password sign-in to SSH off even where
	// it was used lately; PasswordOff turns password sign-in to SSH off.
	RootPasswordOff bool `json:"rootPasswordOff,omitempty"`
	PasswordOff     bool `json:"passwordOff,omitempty"`
	// EPEL lets fail2ban come from EPEL on RHEL and its rebuilds.
	EPEL bool `json:"epel,omitempty"`
}

// maxHardeningList bounds each list option.
const maxHardeningList = 64

// HardeningInput asks for a hardening job on devices.
type HardeningInput struct {
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	Hardening
	// WaitHours is how long to wait for an offline device; zero is the
	// default.
	WaitHours int `json:"waitHours"`
}

// check validates the input and puts its modules and options in their
// canonical form.
func (h *Hardening) check(f apperr.Fields) {
	f.Check(h.Mode == HardeningCheck, "mode", "Choose check.")
	chosen := map[string]bool{}
	for _, m := range h.Modules {
		if !slices.Contains(HardeningModules, m) {
			f.Add("modules", fmt.Sprintf("There is no hardening module %q.", truncateRunes(m, 40)))
			return
		}
		chosen[m] = true
	}
	if len(chosen) == 0 {
		f.Add("modules", "Choose at least one module.")
		return
	}
	h.Modules = slices.DeleteFunc(slices.Clone(HardeningModules), func(m string) bool { return !chosen[m] })
	o := &h.Options
	var bad bool
	if o.AllowTCP, bad = ports(o.AllowTCP); bad {
		f.Add("options.allowTcp", "Enter ports from 1 to 65535, or ranges such as 9000-9100, at most 64.")
	}
	if o.AllowUDP, bad = ports(o.AllowUDP); bad {
		f.Add("options.allowUdp", "Enter ports from 1 to 65535, or ranges such as 9000-9100, at most 64.")
	}
	if o.Trusted, bad = prefixes(o.Trusted); bad {
		f.Add("options.trusted", "Enter addresses or ranges such as 192.0.2.10 or 10.0.0.0/8, at most 64.")
	}
	needs := func(set bool, field, module, name string) {
		f.Check(!set || chosen[module], field, "This option applies to "+name+"; choose that module too.")
	}
	needs(len(o.AllowTCP) > 0, "options.allowTcp", "firewall", "the firewall")
	needs(len(o.AllowUDP) > 0, "options.allowUdp", "firewall", "the firewall")
	needs(len(o.Trusted) > 0, "options.trusted", "fail2ban", "fail2ban")
	needs(o.EPEL, "options.epel", "fail2ban", "fail2ban")
	needs(o.RootPasswordOff, "options.rootPasswordOff", "ssh", "SSH")
	needs(o.PasswordOff, "options.passwordOff", "ssh", "SSH")
}

// ports checks and normalizes port numbers and ranges; bad is true when one
// is not a port or a range.
func ports(in []string) (out []string, bad bool) {
	if len(in) > maxHardeningList {
		return nil, true
	}
	port := func(s string) (int, bool) {
		n, err := strconv.Atoi(s)
		return n, err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == s
	}
	for _, p := range in {
		p = strings.TrimSpace(p)
		lo, hi, isRange := strings.Cut(p, "-")
		a, ok := port(lo)
		if !ok {
			return nil, true
		}
		if isRange {
			b, ok := port(hi)
			if !ok || b < a {
				return nil, true
			}
			if b > a {
				p = lo + "-" + hi
			} else {
				p = lo
			}
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, false
}

// prefixes checks and normalizes addresses and ranges; a single address
// becomes a range of one.
func prefixes(in []string) (out []string, bad bool) {
	if len(in) > maxHardeningList {
		return nil, true
	}
	for _, s := range in {
		s = strings.TrimSpace(s)
		var p netip.Prefix
		if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
			p = netip.PrefixFrom(a, a.BitLen())
		} else if p, err = netip.ParsePrefix(s); err != nil {
			return nil, true
		}
		p = p.Masked()
		if a := p.Addr(); a.Is4In6() {
			return nil, true
		}
		if !slices.Contains(out, p.String()) {
			out = append(out, p.String())
		}
	}
	return out, false
}

// args are the script's arguments: the mode, the modules, then each option.
func (h Hardening) args() []string {
	a := []string{h.Mode, strings.Join(h.Modules, ",")}
	list := func(name string, v []string) {
		if len(v) > 0 {
			a = append(a, name+"="+strings.Join(v, ","))
		}
	}
	list("allow-tcp", h.Options.AllowTCP)
	list("allow-udp", h.Options.AllowUDP)
	list("trusted", h.Options.Trusted)
	for _, sw := range []struct {
		on   bool
		name string
	}{{h.Options.RootPasswordOff, "root-password-off"}, {h.Options.PasswordOff, "password-off"}, {h.Options.EPEL, "epel"}} {
		if sw.on {
			a = append(a, sw.name)
		}
	}
	return a
}

// label names the job for job lists: "Check hardening: ssh, firewall".
func (h Hardening) label() string {
	if len(h.Modules) == len(HardeningModules) {
		return "Check hardening (every module)"
	}
	return "Check hardening: " + strings.Join(h.Modules, ", ")
}

// CreateHardeningJob runs EasyRMM's hardening script on Linux devices
// (ADR-0051). A check changes nothing, and needs script.run on every
// device, as any script does. Every device must pass every check, or
// nothing runs.
func (s *Service) CreateHardeningJob(ctx context.Context, c access.Caller, in HardeningInput) (*Job, error) {
	f := apperr.Fields{}
	ids := checkDevices(f, in.DeviceIDs)
	in.check(f)
	wait := checkWait(f, in.WaitHours)
	if err := f.Err(); err != nil {
		return nil, err
	}
	h := in.Hardening
	sp := &spec{
		kind: KindHardening, hardening: &h, name: h.label(), shell: agentproto.ShellSh, body: hardeningScript, args: h.args(),
		timeout: HardeningTimeout, auditAction: "device.hardening",
		details: map[string]any{"mode": h.Mode, "modules": h.Modules, "options": h.Options},
	}
	r := rule{perm: rbac.PermScriptRun, verb: "check hardening", platforms: []string{"linux"}, runsOn: "Hardening runs on"}
	return s.create(ctx, c, ids, wait, sp, func(ctx context.Context, tx pgx.Tx) ([]target, error) {
		return s.targets(ctx, tx, c, ids, r)
	})
}

// States a module can be in.
const (
	HardeningInPlace          = "in_place"
	HardeningPartly           = "partly"
	HardeningNotInPlace       = "not_in_place"
	HardeningNotApplicable    = "not_applicable"
	HardeningManagedElsewhere = "managed_elsewhere"
	HardeningNotSupported     = "not_supported"
	HardeningHalfApplied      = "half_applied"
	HardeningFailed           = "failed"
)

var hardeningStates = []string{
	HardeningInPlace, HardeningPartly, HardeningNotInPlace, HardeningNotApplicable, HardeningManagedElsewhere,
	HardeningNotSupported, HardeningHalfApplied, HardeningFailed,
}

// HardeningPlatform is the computer as the script saw it.
type HardeningPlatform struct {
	ID        string `json:"id"`
	VersionID string `json:"versionId"`
	// Family is debian, rhel, fedora or other.
	Family string `json:"family"`
	// Container is none, or the kind of container the script ran in.
	Container string `json:"container"`
	// Support is full (check, apply and undo), check_only or unsupported.
	Support string `json:"support"`
}

// HardeningPorts are the firewall's ports: open to TCP and UDP, published
// by Docker past the input hook, and of services enabled but not running.
type HardeningPorts struct {
	TCP     []string `json:"tcp,omitempty"`
	UDP     []string `json:"udp,omitempty"`
	Docker  []string `json:"docker,omitempty"`
	Unknown []string `json:"unknown,omitempty"`
}

// HardeningFinding is what a module's check found besides its state.
type HardeningFinding struct {
	Reason string `json:"reason,omitempty"`
	// Missing lists what is not in place; Changes what apply would change.
	Missing []string        `json:"missing,omitempty"`
	Changes []string        `json:"changes,omitempty"`
	Ports   *HardeningPorts `json:"ports,omitempty"`
}

// HardeningModuleResult is one module's state.
type HardeningModuleResult struct {
	Module string `json:"module"`
	State  string `json:"state"`
	HardeningFinding
}

// hardeningResult is the script's result line.
type hardeningResult struct {
	Version  int                     `json:"version"`
	Mode     string                  `json:"mode"`
	Platform HardeningPlatform       `json:"platform"`
	Modules  []HardeningModuleResult `json:"modules"`
}

// Limits on a result's text, as the script keeps them.
const (
	maxFindingText  = 300
	maxFindingItems = 50
)

var errHardeningResult = errors.New("the hardening script's result could not be read")

// parseHardeningResult reads the result line that ends a hardening job's
// output and checks it against the job: the same mode, every module the job
// named and no other, known states, text within its limits.
func parseHardeningResult(stdout string, h Hardening) (*hardeningResult, error) {
	fail := func(why string) (*hardeningResult, error) {
		return nil, fmt.Errorf("%w: %s", errHardeningResult, why)
	}
	out := strings.TrimRight(stdout, "\r\n\t ")
	line := out[strings.LastIndexByte(out, '\n')+1:]
	if !strings.HasPrefix(line, HardeningResultPrefix) {
		return fail("its output does not end with a result")
	}
	if len(line) > maxHardeningResult {
		return fail("the result is too long")
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(line[len(HardeningResultPrefix):])))
	dec.DisallowUnknownFields()
	var r hardeningResult
	if err := dec.Decode(&r); err != nil {
		return fail("the result is not valid JSON of the expected form")
	}
	if dec.More() {
		return fail("the result has more than one value")
	}
	p := r.Platform
	switch {
	case r.Version != 1:
		return fail(fmt.Sprintf("result version %d is not 1", r.Version))
	case r.Mode != h.Mode:
		return fail("the result is for another mode")
	case !slices.Contains([]string{"debian", "rhel", "fedora", "other"}, p.Family),
		!slices.Contains([]string{"full", "check_only", "unsupported"}, p.Support),
		!shortText(p.ID, 64) || !shortText(p.VersionID, 64) || !shortText(p.Container, 32) || p.Container == "":
		return fail("the platform is not described as expected")
	}
	seen := map[string]bool{}
	for _, m := range r.Modules {
		switch {
		case !slices.Contains(h.Modules, m.Module):
			return fail(fmt.Sprintf("the job did not ask for module %q", truncateRunes(m.Module, 40)))
		case seen[m.Module]:
			return fail("module " + m.Module + " is reported twice")
		case !slices.Contains(hardeningStates, m.State):
			return fail("module " + m.Module + " has an unknown state")
		case !m.valid(m.Module == "firewall"):
			return fail("module " + m.Module + "'s findings are not within their limits")
		}
		seen[m.Module] = true
	}
	if len(seen) != len(h.Modules) {
		return fail("not every module the job asked for is reported")
	}
	return &r, nil
}

// valid says whether a finding's text is within its limits, and ports are
// only the firewall's.
func (f HardeningFinding) valid(firewall bool) bool {
	lists := [][]string{f.Missing, f.Changes}
	if f.Ports != nil {
		if !firewall {
			return false
		}
		lists = append(lists, f.Ports.TCP, f.Ports.UDP, f.Ports.Docker, f.Ports.Unknown)
	}
	if !shortText(f.Reason, maxFindingText) {
		return false
	}
	for _, l := range lists {
		if len(l) > maxFindingItems {
			return false
		}
		for _, s := range l {
			if s == "" || !shortText(s, maxFindingText) {
				return false
			}
		}
	}
	return true
}

// shortText is printable UTF-8 text of at most n characters.
func shortText(s string, n int) bool {
	return utf8.ValidString(s) && utf8.RuneCountInString(s) <= n && cleanText(s, false) == strings.TrimSpace(s)
}

// recordHardening keeps what a successful hardening run reported, per
// module, unless a run that started later has reported already. A result
// that cannot be read fails the run, with the reason.
func (s *Service) recordHardening(ctx context.Context, tx pgx.Tx, device, run, job uuid.UUID, started time.Time, stdout string) error {
	var kind string
	var h *Hardening
	if err := tx.QueryRow(ctx, `SELECT kind, hardening FROM jobs WHERE id = $1`, job).Scan(&kind, &h); err != nil {
		return err
	}
	if kind != KindHardening {
		return nil
	}
	r, err := parseHardeningResult(stdout, *h)
	if err != nil {
		s.log.Warn("jobs: a hardening run's result was refused", "run", run, "device", device, "error", err)
		_, err := tx.Exec(ctx, `UPDATE job_runs SET status = 'failed', error = $2 WHERE id = $1`,
			run, truncateRunes("The script finished, but "+strings.TrimPrefix(err.Error(), "the ")+".", 2000))
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO device_hardening_checks (device_id, platform, job_id, checked_at)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (device_id) DO UPDATE SET platform = EXCLUDED.platform, job_id = EXCLUDED.job_id,
				checked_at = EXCLUDED.checked_at
			WHERE device_hardening_checks.checked_at <= EXCLUDED.checked_at`,
		device, r.Platform, job, started); err != nil {
		return err
	}
	for _, m := range r.Modules {
		if _, err := tx.Exec(ctx, `INSERT INTO device_hardening (device_id, module, state, detail, job_id, checked_at)
				VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (device_id, module) DO UPDATE SET state = EXCLUDED.state, detail = EXCLUDED.detail,
					job_id = EXCLUDED.job_id, checked_at = EXCLUDED.checked_at
				WHERE device_hardening.checked_at <= EXCLUDED.checked_at`,
			device, m.Module, m.State, m.HardeningFinding, job, started); err != nil {
			return err
		}
	}
	return nil
}

// DeviceHardening is what the last hardening jobs found on a device.
type DeviceHardening struct {
	// Platform, JobID and CheckedAt are from the latest job; nil until a
	// hardening job reported.
	Platform  *HardeningPlatform `json:"platform"`
	JobID     *uuid.UUID         `json:"jobId"`
	CheckedAt *time.Time         `json:"checkedAt"`
	// Modules has each module the device was checked for, in the order of
	// HardeningModules, with the job that last covered it.
	Modules []HardeningModuleState `json:"modules"`
}

// HardeningModuleState is a module's state as a job found it.
type HardeningModuleState struct {
	HardeningModuleResult
	JobID     *uuid.UUID `json:"jobId"`
	CheckedAt time.Time  `json:"checkedAt"`
}

// DeviceHardening returns what hardening jobs found on a device. It needs
// device.view.
func (s *Service) DeviceHardening(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*DeviceHardening, error) {
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermDeviceView, rbac.Site(d.OrganizationID, d.SiteID)) {
		return nil, apperr.Forbidden()
	}
	out := &DeviceHardening{Modules: []HardeningModuleState{}}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var p HardeningPlatform
		var at time.Time
		err := tx.QueryRow(ctx, `SELECT platform, job_id, checked_at FROM device_hardening_checks WHERE device_id = $1`,
			deviceID).Scan(&p, &out.JobID, &at)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		out.Platform, out.CheckedAt = &p, &at
		rows, err := tx.Query(ctx, `SELECT module, state, detail, job_id, checked_at FROM device_hardening
			WHERE device_id = $1 ORDER BY array_position($2::text[], module)`, deviceID, HardeningModules)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m HardeningModuleState
			if err := rows.Scan(&m.Module, &m.State, &m.HardeningFinding, &m.JobID, &m.CheckedAt); err != nil {
				return err
			}
			out.Modules = append(out.Modules, m)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
