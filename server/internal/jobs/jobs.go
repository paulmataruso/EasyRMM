package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Job runs a snapshot of a script on devices: a library script, or one of
// EasyRMM's own for a software action. Counts and runs cover only the runs
// the caller can see.
type Job struct {
	ID uuid.UUID `json:"id"`
	// Kind is KindScript, KindSoftware or KindHardening; Software is the
	// software action, Hardening what a hardening job does.
	Kind       string     `json:"kind"`
	Software   *Software  `json:"software"`
	Hardening  *Hardening `json:"hardening"`
	ScriptID   *uuid.UUID `json:"scriptId"`
	ScriptName string     `json:"scriptName"`
	Shell      string     `json:"shell"`
	// PwshFallback is the script's setting, copied into the job: a pwsh
	// run may use Windows PowerShell 5.1 where PowerShell 7 is missing.
	PwshFallback   bool      `json:"pwshFallback"`
	SHA256         string    `json:"sha256"`
	TimeoutSeconds int       `json:"timeoutSeconds"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedBy      string    `json:"createdBy"`
	CreatedAt      time.Time `json:"createdAt"`
	// Counts has a count for every status.
	Counts map[string]int `json:"counts"`
	Total  int            `json:"total"`
	// Finished is true once every visible run has ended.
	Finished bool `json:"finished"`
	// Body and Runs are filled in by GetJob only.
	Body string `json:"body,omitempty"`
	Runs []*Run `json:"runs,omitempty"`
	// JobDetail is filled in by GetJob only.
	*JobDetail
	// CanCancel says whether the caller may cancel a run still open.
	CanCancel bool `json:"canCancel"`
}

// JobDetail is what the job's page needs about its arguments. Their values
// come from ReadArguments only, never with a job (ADR-0063).
type JobDetail struct {
	ArgCount int `json:"argCount"`
	// CanViewArguments says whether the caller holds job.view_sensitive at
	// the site of one of the runs they can see.
	CanViewArguments bool `json:"canViewArguments"`
	// CanDownloadOutput says whether the job's output archive would hold
	// something: a finished run the caller sees, at a site where they hold
	// job.view_sensitive (ADR-0064).
	CanDownloadOutput bool `json:"canDownloadOutput"`
}

// Run is one device's part of a job.
type Run struct {
	ID               uuid.UUID  `json:"id"`
	JobID            uuid.UUID  `json:"jobId"`
	DeviceID         uuid.UUID  `json:"deviceId"`
	DeviceName       string     `json:"deviceName"`
	OrganizationID   uuid.UUID  `json:"organizationId"`
	OrganizationName string     `json:"organizationName"`
	SiteID           uuid.UUID  `json:"siteId"`
	SiteName         string     `json:"siteName"`
	ScriptName       string     `json:"scriptName"`
	Status           string     `json:"status"`
	CreatedAt        time.Time  `json:"createdAt"`
	ExpiresAt        time.Time  `json:"expiresAt"`
	SentAt           *time.Time `json:"sentAt"`
	Deliveries       int        `json:"deliveries"`
	StartedAt        *time.Time `json:"startedAt"`
	FinishedAt       *time.Time `json:"finishedAt"`
	ExitCode         *int       `json:"exitCode"`
	Error            string     `json:"error"`
	CancelRequested  bool       `json:"cancelRequested"`
	// Program is the program the agent started, as it reported it; nil
	// when it reported none: the run did not start, or its agent is too
	// old to say (ADR-0064). Everyone who sees the run sees it.
	Program *Program `json:"program"`
	// Held says why a queued run is not delivered, or a delivered run that
	// has not started is not delivered again: HeldUnable when the device's
	// agent said it cannot run it, HeldUnreported when the build it runs
	// has not said yet. A delivered run is held when the agent changed
	// builds after taking it, as a rollback does. Empty otherwise.
	Held string `json:"held,omitempty"`
	// Job and RunDetail are filled in by GetRun only.
	Job *Job `json:"job,omitempty"`
	*RunDetail

	CanCancel bool `json:"canCancel"`
}

// RunDetail is what the run's page needs about its output. The output
// itself comes from ReadOutput only, never with a run (ADR-0063).
type RunDetail struct {
	// CanViewOutput says whether the caller holds job.view_sensitive at
	// the run's site.
	CanViewOutput bool `json:"canViewOutput"`
	// CanRemoveOutput says whether the caller may remove the output: it
	// takes job.view_sensitive and job.manage at the run's site.
	CanRemoveOutput bool `json:"canRemoveOutput"`
	// OutputState is there only when CanViewOutput is.
	*OutputState
}

// OutputState says whether a run has output to read, without reading it.
type OutputState struct {
	StdoutBytes int `json:"stdoutBytes"`
	StderrBytes int `json:"stderrBytes"`
	// OutputRemovedAt is when retention or a person removed the output.
	OutputRemovedAt *time.Time `json:"outputRemovedAt"`
}

// Program is the program a run started (agentproto.Interpreter, as kept).
type Program struct {
	// Edition is "Desktop" (Windows PowerShell) or "Core" (PowerShell 7),
	// empty for other shells.
	Edition string `json:"edition,omitempty"`
	Version string `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Path    string `json:"path"`
	// Fallback: a pwsh script ran in Windows PowerShell 5.1, as it allows,
	// because no usable PowerShell 7 was found.
	Fallback bool `json:"fallback,omitempty"`
}

// Why a queued or delivered run waits (Run.Held).
const (
	HeldUnable     = "unable"
	HeldUnreported = "unreported"
)

// acceptsNow is the SQL form of what a device d's agent last said it
// accepts (agentproto.PollRequest.Accepts), NULL when the build it runs now
// has not said: a list holds for the build that sent it (ADR-0064).
const acceptsNow = `(CASE WHEN d.agent_accepts_build IS NOT DISTINCT FROM coalesce(d.agent_sha256, d.agent_version) THEN d.agent_accepts END)`

// heldSQL is the SQL form of Run.Held, for a run r of job j on device d.
const heldSQL = `CASE WHEN r.status NOT IN ('queued', 'sent') OR j.requires <@ coalesce(` + acceptsNow + `, '{}') THEN ''
	WHEN ` + acceptsNow + ` IS NULL THEN 'unreported' ELSE 'unable' END`

func (r *Run) open() bool {
	return r.Status == StatusQueued || r.Status == StatusSent || r.Status == StatusRunning
}

const runColumns = `r.id, r.job_id, r.device_id, d.name, r.organization_id, o.name, r.site_id, si.name, j.script_name,
	r.status, r.created_at, r.expires_at, r.sent_at, r.deliveries, r.started_at, r.finished_at, r.exit_code, r.error,
	r.cancel_requested_at IS NOT NULL, coalesce(r.program_edition, ''), coalesce(r.program_version, ''),
	coalesce(r.program_arch, ''), r.program_path, r.program_fallback, ` + heldSQL

const runFrom = ` FROM job_runs r
	JOIN jobs j ON j.id = r.job_id
	JOIN devices d ON d.id = r.device_id
	JOIN organizations o ON o.id = r.organization_id
	JOIN sites si ON si.id = r.site_id`

func scanRun(row pgx.Row, extra ...any) (*Run, error) {
	var (
		r    Run
		p    Program
		path *string
	)
	dst := append([]any{&r.ID, &r.JobID, &r.DeviceID, &r.DeviceName, &r.OrganizationID, &r.OrganizationName, &r.SiteID, &r.SiteName, &r.ScriptName,
		&r.Status, &r.CreatedAt, &r.ExpiresAt, &r.SentAt, &r.Deliveries, &r.StartedAt, &r.FinishedAt, &r.ExitCode, &r.Error,
		&r.CancelRequested, &p.Edition, &p.Version, &p.Arch, &path, &p.Fallback, &r.Held}, extra...)
	if err := row.Scan(dst...); err != nil {
		return nil, err
	}
	if path != nil {
		p.Path = *path
		r.Program = &p
	}
	return &r, nil
}

func (s *Service) decorateRun(c access.Caller, r *Run) {
	r.CanCancel = r.open() && !r.CancelRequested && c.Can(rbac.PermJobManage, rbac.Site(r.OrganizationID, r.SiteID))
}

// JobInput starts a job.
type JobInput struct {
	ScriptID  uuid.UUID   `json:"scriptId"`
	DeviceIDs []uuid.UUID `json:"deviceIds"`
	Args      []string    `json:"args"`
	// TimeoutSeconds overrides the script's default when not zero.
	TimeoutSeconds int `json:"timeoutSeconds"`
	// WaitHours is how long to wait for an offline device; zero is the
	// default.
	WaitHours int `json:"waitHours"`
}

// target is a device a job is about to run on.
type target struct {
	id, org, site  uuid.UUID
	name, platform string
	enrolled       bool
	// accepts is what its agent's build last said it accepts; nil when
	// that build has not said.
	accepts []string
}

// CreateJob runs a library script on devices. Every device must pass every
// check, or nothing runs.
func (s *Service) CreateJob(ctx context.Context, c access.Caller, in JobInput) (*Job, error) {
	f := apperr.Fields{}
	ids := checkDevices(f, in.DeviceIDs)
	args := in.Args
	if args == nil {
		args = []string{}
	}
	f.Check(len(args) <= MaxArgs, "args", fmt.Sprintf("Use at most %d arguments.", MaxArgs))
	for i, a := range args {
		switch {
		case len(a) > MaxArgBytes:
			f.Add("args", fmt.Sprintf("Argument %d is longer than 1 KiB.", i+1))
		case !utf8.ValidString(a) || strings.ContainsRune(a, 0):
			f.Add("args", fmt.Sprintf("Argument %d must be text without NUL characters.", i+1))
		}
	}
	if in.TimeoutSeconds != 0 {
		checkTimeout(f, in.TimeoutSeconds)
	}
	wait := checkWait(f, in.WaitHours)
	if in.ScriptID == uuid.Nil {
		f.Add("scriptId", "Choose a script.")
	}
	if err := f.Err(); err != nil {
		return nil, err
	}

	sp := &spec{}
	return s.create(ctx, c, ids, wait, sp, func(ctx context.Context, tx pgx.Tx) ([]target, error) {
		sc, err := s.getScript(ctx, tx, c, in.ScriptID, false)
		if errors.Is(err, apperr.ErrNotFound) {
			return nil, apperr.Invalid("scriptId", "That script does not exist or you cannot read it.")
		}
		if err != nil {
			return nil, err
		}
		if sc.Shell == agentproto.ShellCmd {
			for i, a := range args {
				if strings.ContainsAny(a, CmdArgForbidden) {
					return nil, apperr.Invalid("args", fmt.Sprintf("Argument %d contains %%, a double quote or a line break, which cmd would read as part of the command. Use a PowerShell script to pass it.", i+1))
				}
			}
		}
		timeout := sc.TimeoutSeconds
		if in.TimeoutSeconds != 0 {
			timeout = in.TimeoutSeconds
		}
		details := map[string]any{"script": sc.Name, "scriptId": sc.ID.String(), "shell": sc.Shell, "argCount": len(args)}
		if sc.Shell == agentproto.ShellPwsh {
			details["pwshFallback"] = sc.PwshFallback
		}
		*sp = spec{
			kind: KindScript, scriptID: &sc.ID, name: sc.Name, shell: sc.Shell, pwshFallback: sc.PwshFallback, body: sc.Body, args: args,
			timeout: timeout, auditAction: "device.script_run", details: details,
		}
		org, site := sc.level()
		return s.targets(ctx, tx, c, ids, rule{
			perm: rbac.PermScriptRun, verb: "run scripts", org: org, site: site,
			platforms: agentproto.ShellPlatforms(sc.Shell), runsOn: shellName(sc.Shell) + " scripts run on",
			requires: agentproto.ShellRequires(sc.Shell), what: shellName(sc.Shell) + " scripts",
		})
	})
}

// CmdArgForbidden are the characters a cmd script's argument cannot hold.
// Quoting protects the rest, but cmd expands %variables% inside quotes, so
// an argument like %CMDCMDLINE:~-1% would end the quotes and run whatever
// follows; the agent refuses them too.
const CmdArgForbidden = "%\"\r\n"

// checkDevices validates a job's device ids and returns them sorted,
// without duplicates.
func checkDevices(f apperr.Fields, in []uuid.UUID) []uuid.UUID {
	ids := slices.Clone(in)
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	ids = slices.Compact(ids)
	switch {
	case len(ids) == 0:
		f.Add("deviceIds", "Choose at least one device.")
	case len(ids) > MaxDevices:
		f.Add("deviceIds", fmt.Sprintf("Choose at most %d devices.", MaxDevices))
	case slices.Contains(ids, uuid.Nil):
		f.Add("deviceIds", "A device id is missing.")
	}
	return ids
}

func checkTimeout(f apperr.Fields, seconds int) {
	f.Check(seconds >= MinTimeout && seconds <= MaxTimeout, "timeoutSeconds", "Use 1 second to 4 hours.")
}

// checkWait validates how long a job waits for offline devices and returns
// it, the default for zero.
func checkWait(f apperr.Fields, hours int) int {
	if hours == 0 {
		hours = DefaultWaitHours
	}
	f.Check(hours >= MinWaitHours && hours <= MaxWaitHours, "waitHours", "Wait 1 hour to 7 days.")
	return hours
}

// spec is what a new job runs, and how its runs are audited.
type spec struct {
	kind      string
	scriptID  *uuid.UUID
	software  *Software
	hardening *Hardening
	name      string
	shell     string
	// pwshFallback is the script's setting, for a pwsh job.
	pwshFallback bool
	body         string
	args         []string
	timeout      int
	// auditAction and details describe each run in the audit log, with the
	// device, job, script hash and timeout added.
	auditAction string
	details     map[string]any
}

// create inserts a job and its runs. resolve finds and checks the devices
// in the job's transaction, and may fill in sp there: a library script is
// read in the same transaction.
func (s *Service) create(ctx context.Context, c access.Caller, ids []uuid.UUID, wait int, sp *spec,
	resolve func(context.Context, pgx.Tx) ([]target, error)) (*Job, error) {
	jobID := uuid.New()
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		targets, err := resolve(ctx, tx)
		if err != nil {
			return err
		}
		now := s.now()
		expires := now.Add(time.Duration(wait) * time.Hour)
		sum := sha256.Sum256([]byte(sp.body))
		if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, script_id, script_name, shell, body, body_sha256, args, timeout_seconds,
				expires_at, created_by, created_by_label, created_at, kind, software, hardening, pwsh_fallback, requires)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
			jobID, sp.scriptID, sp.name, sp.shell, sp.body, sum[:], sp.args, sp.timeout, expires, nullUUID(c.Actor.ID),
			truncateRunes(c.Actor.Label, 320), now, sp.kind, sp.software, sp.hardening, sp.pwshFallback,
			agentproto.ShellRequires(sp.shell)); err != nil {
			return err
		}
		for _, t := range targets {
			var runID uuid.UUID
			if err := tx.QueryRow(ctx, `INSERT INTO job_runs (job_id, organization_id, site_id, device_id, expires_at, created_at)
				VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, jobID, t.org, t.site, t.id, expires, now).Scan(&runID); err != nil {
				return err
			}
			details := map[string]any{
				"device": t.name, "jobId": jobID.String(), "sha256": hex.EncodeToString(sum[:]), "timeoutSeconds": sp.timeout,
			}
			for k, v := range sp.details {
				details[k] = v
			}
			if err := s.audit.Write(ctx, tx, audit.Event{
				Actor: c.Actor, Action: sp.auditAction, Outcome: audit.Success,
				OrganizationID: t.org, SiteID: t.site, DeviceID: t.id, TargetType: "job_run", TargetID: runID.String(),
				Details: details,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.hub.notify(ids...)
	return s.GetJob(ctx, c, jobID)
}

// rule is who may start a job on which devices.
type rule struct {
	perm rbac.Permission
	verb string // "run scripts"
	// org and site limit the devices to a script's organization or site.
	org, site uuid.UUID
	platforms []string
	runsOn    string // "Bash scripts run on"
	// requires lists the capabilities the device's agent must accept
	// (agentproto.ShellRequires); what names the jobs that need them.
	requires []string
	what     string // "PowerShell 7 scripts"
}

// targets resolves and checks the devices of a new job.
func (s *Service) targets(ctx context.Context, tx pgx.Tx, c access.Caller, ids []uuid.UUID, r rule) ([]target, error) {
	rows, err := tx.Query(ctx, `SELECT d.id, d.organization_id, d.site_id, d.name, d.platform, d.agent_public_key IS NOT NULL, `+acceptsNow+`
		FROM devices d WHERE d.id = ANY ($1) ORDER BY lower(d.name), d.id`, ids)
	if err != nil {
		return nil, err
	}
	var found []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.org, &t.site, &t.name, &t.platform, &t.enrolled, &t.accepts); err != nil {
			rows.Close()
			return nil, err
		}
		if c.Can(rbac.PermDeviceView, rbac.Site(t.org, t.site)) {
			found = append(found, t)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if missing := len(ids) - len(found); missing > 0 {
		return nil, apperr.Invalid("deviceIds", fmt.Sprintf("%d %s", missing, pick(missing, "device does not exist or is not visible to you.", "devices do not exist or are not visible to you.")))
	}
	var forbidden, outside, noAgent, wrongOS, unable, unreported []string
	for _, t := range found {
		switch {
		case !c.Can(r.perm, rbac.Site(t.org, t.site)):
			forbidden = append(forbidden, t.name)
		case !covers(r.org, r.site, t.org, t.site):
			outside = append(outside, t.name)
		case !t.enrolled:
			noAgent = append(noAgent, t.name)
		case !slices.Contains(r.platforms, t.platform):
			wrongOS = append(wrongOS, t.name)
		case len(r.requires) > 0 && t.accepts == nil:
			unreported = append(unreported, t.name)
		case !containsAll(t.accepts, r.requires):
			unable = append(unable, t.name)
		}
	}
	switch {
	case len(forbidden) > 0:
		return nil, apperr.Invalid("deviceIds", "You cannot "+r.verb+" on "+names(forbidden)+".")
	case len(outside) > 0:
		where := "its organization"
		if r.site != uuid.Nil {
			where = "its site"
		}
		return nil, apperr.Invalid("deviceIds", "This script runs only on devices in "+where+", not on "+names(outside)+".")
	case len(noAgent) > 0:
		return nil, apperr.Invalid("deviceIds", names(noAgent)+" "+pick(len(noAgent), "has", "have")+" no EasyRMM agent to "+r.verb+".")
	case len(wrongOS) > 0:
		os := platformName(r.platforms)
		return nil, apperr.Invalid("deviceIds", r.runsOn+" "+os+"; "+names(wrongOS)+" "+pick(len(wrongOS), "is", "are")+" not "+article(os)+" "+os+" device.")
	case len(unable) == 1:
		return nil, apperr.Invalid("deviceIds", unable[0]+"'s agent cannot run "+r.what+"; update the agent.")
	case len(unable) > 0:
		return nil, apperr.Invalid("deviceIds", "The agents of "+names(unable)+" cannot run "+r.what+"; update them.")
	case len(unreported) == 1:
		return nil, apperr.Invalid("deviceIds", unreported[0]+"'s agent has not yet said whether it can run "+r.what+"; try again in a minute, and update the agent if it still has not.")
	case len(unreported) > 0:
		return nil, apperr.Invalid("deviceIds", "The agents of "+names(unreported)+" have not yet said whether they can run "+r.what+"; try again in a minute, and update them if they still have not.")
	}
	return found, nil
}

// containsAll reports whether list holds every one of want.
func containsAll(list, want []string) bool {
	for _, w := range want {
		if !slices.Contains(list, w) {
			return false
		}
	}
	return true
}

// shellName is how people write a shell's name.
func shellName(shell string) string {
	switch shell {
	case agentproto.ShellPowerShell:
		return "Windows PowerShell 5.1"
	case agentproto.ShellPwsh:
		return "PowerShell 7"
	case agentproto.ShellCmd:
		return "cmd"
	}
	return shell
}

// platformName names the platform a shell runs on.
func platformName(platforms []string) string {
	if len(platforms) > 0 && platforms[0] == "windows" {
		return "Windows"
	}
	return "Linux"
}

func article(word string) string {
	if word != "" && strings.ContainsRune("AEIOU", rune(word[0])) {
		return "an"
	}
	return "a"
}

// names lists up to three names, then how many more.
func names(list []string) string {
	if len(list) <= 3 {
		switch len(list) {
		case 1:
			return list[0]
		case 2:
			return list[0] + " and " + list[1]
		default:
			return list[0] + ", " + list[1] + " and " + list[2]
		}
	}
	return fmt.Sprintf("%s, %s, %s and %d more", list[0], list[1], list[2], len(list)-3)
}

// pick chooses the singular or plural form.
func pick(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// JobQuery filters the job list.
type JobQuery struct {
	// OrganizationID, SiteID and DeviceID list the jobs with a run there.
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	DeviceID       uuid.UUID
	ScriptID       uuid.UUID
	// Status is "", "open" (some run has not ended) or "finished".
	Status string
	// Kind is "", KindScript or KindSoftware.
	Kind string
}

// jobColumns leaves out the arguments: the server's database role cannot
// read them (ADR-0063).
const jobColumns = `j.id, j.kind, j.software, j.hardening, j.script_id, j.script_name, j.shell, j.pwsh_fallback, encode(j.body_sha256, 'hex'),
	j.timeout_seconds, j.expires_at, j.created_by_label, j.created_at`

// jobDest is where jobColumns are scanned into.
func jobDest(j *Job) []any {
	return []any{&j.ID, &j.Kind, &j.Software, &j.Hardening, &j.ScriptID, &j.ScriptName, &j.Shell, &j.PwshFallback, &j.SHA256,
		&j.TimeoutSeconds, &j.ExpiresAt, &j.CreatedBy, &j.CreatedAt}
}

func scanJob(row pgx.Row, extra ...any) (*Job, error) {
	var j Job
	dst := append(jobDest(&j), extra...)
	if err := row.Scan(dst...); err != nil {
		return nil, err
	}
	return &j, nil
}

// ListJobs returns the newest jobs the caller can see, with the counts of
// their visible runs.
func (s *Service) ListJobs(ctx context.Context, c access.Caller, q JobQuery) ([]*Job, error) {
	switch q.Status {
	case "", "open", "finished":
	default:
		return nil, apperr.Invalid("status", "Use open or finished.")
	}
	switch q.Kind {
	case "", KindScript, KindSoftware, KindHardening:
	default:
		return nil, apperr.Invalid("kind", "Use script, software or hardening.")
	}
	if !c.CanAnywhere(rbac.PermJobView) {
		return []*Job{}, nil
	}
	out := []*Job{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+jobColumns+`, c.statuses, c.counts, c.can_cancel_sites
			FROM jobs j
			JOIN LATERAL (
				SELECT array_agg(st.status ORDER BY st.status) AS statuses, array_agg(st.n ORDER BY st.status) AS counts,
				       (SELECT array_agg(DISTINCT r2.organization_id::text || '/' || r2.site_id::text) FROM job_runs r2
				         WHERE r2.job_id = j.id AND r2.status IN ('queued', 'sent', 'running') AND r2.cancel_requested_at IS NULL) AS can_cancel_sites
				FROM (SELECT r.status, count(*)::int AS n FROM job_runs r WHERE r.job_id = j.id GROUP BY r.status) st
			) c ON c.statuses IS NOT NULL
			WHERE ($1::uuid IS NULL OR EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = j.id AND r.device_id = $1))
			  AND ($2::uuid IS NULL OR j.script_id = $2)
			  AND ($3 = '' OR EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = j.id AND r.status IN ('queued', 'sent', 'running')) = ($3 = 'open'))
			  AND ($5::uuid IS NULL OR EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = j.id AND r.organization_id = $5))
			  AND ($6::uuid IS NULL OR EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = j.id AND r.site_id = $6))
			  AND ($7 = '' OR j.kind = $7)
			ORDER BY j.created_at DESC, j.id LIMIT $4`,
			nullUUID(q.DeviceID), nullUUID(q.ScriptID), q.Status, MaxList, nullUUID(q.OrganizationID), nullUUID(q.SiteID), q.Kind)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				statuses []string
				counts   []int32
				open     []string
			)
			j, err := scanJob(rows, &statuses, &counts, &open)
			if err != nil {
				return err
			}
			s.fillCounts(j, statuses, counts)
			j.CanCancel = canCancelAny(c, open)
			out = append(out, j)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Service) fillCounts(j *Job, statuses []string, counts []int32) {
	j.Counts = map[string]int{}
	for _, st := range Statuses {
		j.Counts[st] = 0
	}
	j.Total = 0
	for i, st := range statuses {
		j.Counts[st] = int(counts[i])
		j.Total += int(counts[i])
	}
	j.Finished = j.Counts[StatusQueued]+j.Counts[StatusSent]+j.Counts[StatusRunning] == 0
}

// canCancelAny reports whether the caller may cancel runs in any of the
// "org/site" pairs.
func canCancelAny(c access.Caller, pairs []string) bool {
	for _, p := range pairs {
		org, site, ok := strings.Cut(p, "/")
		if !ok {
			continue
		}
		o, err1 := uuid.Parse(org)
		si, err2 := uuid.Parse(site)
		if err1 == nil && err2 == nil && c.Can(rbac.PermJobManage, rbac.Site(o, si)) {
			return true
		}
	}
	return false
}

// GetJob returns a job with its script and the runs the caller can see.
func (s *Service) GetJob(ctx context.Context, c access.Caller, id uuid.UUID) (*Job, error) {
	var j *Job
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var body string
		var err error
		detail := &JobDetail{}
		j, err = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+`, j.body, j.arg_count FROM jobs j WHERE j.id = $1`, id), &body, &detail.ArgCount)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		j.Body, j.JobDetail = body, detail
		rows, err := tx.Query(ctx, `SELECT `+runColumns+runFrom+` WHERE r.job_id = $1 ORDER BY lower(d.name), r.id`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		j.Runs = []*Run{}
		for rows.Next() {
			r, err := scanRun(rows)
			if err != nil {
				return err
			}
			if !c.Can(rbac.PermJobView, rbac.Site(r.OrganizationID, r.SiteID)) {
				continue
			}
			s.decorateRun(c, r)
			j.CanCancel = j.CanCancel || r.CanCancel
			sensitive := c.Can(rbac.PermJobViewSensitive, rbac.Site(r.OrganizationID, r.SiteID))
			detail.CanViewArguments = detail.CanViewArguments || sensitive
			detail.CanDownloadOutput = detail.CanDownloadOutput || (sensitive && !r.open())
			j.Runs = append(j.Runs, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(j.Runs) == 0 {
		return nil, apperr.NotFound()
	}
	var statuses []string
	var counts []int32
	byStatus := map[string]int32{}
	for _, r := range j.Runs {
		byStatus[r.Status]++
	}
	for _, st := range Statuses {
		if n := byStatus[st]; n > 0 {
			statuses, counts = append(statuses, st), append(counts, n)
		}
	}
	s.fillCounts(j, statuses, counts)
	return j, nil
}

// RunQuery filters the run list.
type RunQuery struct {
	DeviceID uuid.UUID
	// Kind is "" or a job kind: a device's hardening runs, for its
	// Hardening tab.
	Kind string
}

// ListRuns returns a device's newest runs.
func (s *Service) ListRuns(ctx context.Context, c access.Caller, q RunQuery) ([]*Run, error) {
	if q.DeviceID == uuid.Nil {
		return nil, apperr.Invalid("deviceId", "Choose a device.")
	}
	switch q.Kind {
	case "", KindScript, KindSoftware, KindHardening:
	default:
		return nil, apperr.Invalid("kind", "Use script, software or hardening.")
	}
	out := []*Run{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+runColumns+runFrom+` WHERE r.device_id = $1 AND ($3 = '' OR j.kind = $3)
			ORDER BY r.created_at DESC, r.id LIMIT $2`,
			q.DeviceID, MaxList, q.Kind)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRun(rows)
			if err != nil {
				return err
			}
			if !c.Can(rbac.PermJobView, rbac.Site(r.OrganizationID, r.SiteID)) {
				continue
			}
			s.decorateRun(c, r)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// GetRun returns a run with its job, and whether its output can be read.
func (s *Service) GetRun(ctx context.Context, c access.Caller, id uuid.UUID) (*Run, error) {
	var r *Run
	state := &OutputState{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var body string
		var err error
		job := &Job{}
		dst := append(append([]any{&state.StdoutBytes, &state.StderrBytes, &state.OutputRemovedAt}, jobDest(job)...), &body)
		r, err = scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+`, r.stdout_bytes, r.stderr_bytes, r.output_removed_at, `+jobColumns+`, j.body`+
			runFrom+` WHERE r.id = $1`, id), dst...)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		job.Body = body
		r.Job = job
		return nil
	})
	if err != nil {
		return nil, err
	}
	at := rbac.Site(r.OrganizationID, r.SiteID)
	if !c.Can(rbac.PermJobView, at) {
		return nil, apperr.NotFound()
	}
	s.decorateRun(c, r)
	r.RunDetail = &RunDetail{CanViewOutput: c.Can(rbac.PermJobViewSensitive, at), CanRemoveOutput: canRemoveOutput(c, at)}
	if r.CanViewOutput {
		r.OutputState = state
	}
	return r, nil
}

// CancelJob cancels every open run of a job the caller may cancel.
func (s *Service) CancelJob(ctx context.Context, c access.Caller, id uuid.UUID) (*Job, error) {
	if err := s.cancel(ctx, c, `r.job_id = $1`, id); err != nil {
		return nil, err
	}
	return s.GetJob(ctx, c, id)
}

// CancelRun cancels one run.
func (s *Service) CancelRun(ctx context.Context, c access.Caller, id uuid.UUID) (*Run, error) {
	if err := s.cancel(ctx, c, `r.id = $1`, id); err != nil {
		return nil, err
	}
	return s.GetRun(ctx, c, id)
}

// cancel ends the open runs matching where: queued and delivered runs at
// once, running ones by asking the agent to stop them.
func (s *Service) cancel(ctx context.Context, c access.Caller, where string, id uuid.UUID) error {
	var notify []uuid.UUID
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+runColumns+runFrom+` WHERE `+where+` ORDER BY lower(d.name), r.id FOR UPDATE OF r`, id)
		if err != nil {
			return err
		}
		var runs []*Run
		for rows.Next() {
			r, err := scanRun(rows)
			if err != nil {
				rows.Close()
				return err
			}
			if c.Can(rbac.PermJobView, rbac.Site(r.OrganizationID, r.SiteID)) {
				runs = append(runs, r)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(runs) == 0 {
			return apperr.NotFound()
		}
		allowed, open := 0, 0
		for _, r := range runs {
			if !r.open() || r.CancelRequested {
				continue
			}
			open++
			if !c.Can(rbac.PermJobManage, rbac.Site(r.OrganizationID, r.SiteID)) {
				continue
			}
			allowed++
			if r.Status == StatusRunning {
				_, err = tx.Exec(ctx, `UPDATE job_runs SET cancel_requested_at = now(), canceled_by = $2 WHERE id = $1`, r.ID, nullUUID(c.Actor.ID))
				notify = append(notify, r.DeviceID)
			} else {
				_, err = tx.Exec(ctx, `UPDATE job_runs SET status = 'canceled', finished_at = now(), cancel_requested_at = now(), canceled_by = $2,
					error = 'Canceled before it started.' WHERE id = $1`, r.ID, nullUUID(c.Actor.ID))
			}
			if err != nil {
				return err
			}
			if err := s.audit.Write(ctx, tx, audit.Event{
				Actor: c.Actor, Action: "job.cancel", Outcome: audit.Success,
				OrganizationID: r.OrganizationID, SiteID: r.SiteID, DeviceID: r.DeviceID, TargetType: "job_run", TargetID: r.ID.String(),
				Details: map[string]any{"device": r.DeviceName, "script": r.ScriptName, "jobId": r.JobID.String(), "status": r.Status},
			}); err != nil {
				return err
			}
		}
		switch {
		case open == 0:
			return apperr.Conflict("job_finished", "Nothing to cancel: every run has already ended.")
		case allowed == 0:
			return apperr.Forbidden()
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.hub.notify(notify...)
	return nil
}
