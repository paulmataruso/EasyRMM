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

// Job runs a snapshot of a script on devices. Counts and runs cover only the
// runs the caller can see.
type Job struct {
	ID             uuid.UUID  `json:"id"`
	ScriptID       *uuid.UUID `json:"scriptId"`
	ScriptName     string     `json:"scriptName"`
	Shell          string     `json:"shell"`
	SHA256         string     `json:"sha256"`
	Args           []string   `json:"args"`
	TimeoutSeconds int        `json:"timeoutSeconds"`
	ExpiresAt      time.Time  `json:"expiresAt"`
	CreatedBy      string     `json:"createdBy"`
	CreatedAt      time.Time  `json:"createdAt"`
	// Counts has a count for every status.
	Counts map[string]int `json:"counts"`
	Total  int            `json:"total"`
	// Finished is true once every visible run has ended.
	Finished bool `json:"finished"`
	// Body and Runs are filled in by GetJob only.
	Body string `json:"body,omitempty"`
	Runs []*Run `json:"runs,omitempty"`
	// CanCancel says whether the caller may cancel a run still open.
	CanCancel bool `json:"canCancel"`
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
	StdoutTruncated  bool       `json:"stdoutTruncated"`
	StderrTruncated  bool       `json:"stderrTruncated"`
	CancelRequested  bool       `json:"cancelRequested"`
	// Output is filled in by GetRun only.
	Stdout *string `json:"stdout,omitempty"`
	Stderr *string `json:"stderr,omitempty"`
	// Job is filled in by GetRun only.
	Job *Job `json:"job,omitempty"`

	CanCancel bool `json:"canCancel"`
}

func (r *Run) open() bool {
	return r.Status == StatusQueued || r.Status == StatusSent || r.Status == StatusRunning
}

const runColumns = `r.id, r.job_id, r.device_id, d.name, r.organization_id, o.name, r.site_id, si.name, j.script_name,
	r.status, r.created_at, r.expires_at, r.sent_at, r.deliveries, r.started_at, r.finished_at, r.exit_code, r.error,
	r.stdout_truncated, r.stderr_truncated, r.cancel_requested_at IS NOT NULL`

const runFrom = ` FROM job_runs r
	JOIN jobs j ON j.id = r.job_id
	JOIN devices d ON d.id = r.device_id
	JOIN organizations o ON o.id = r.organization_id
	JOIN sites si ON si.id = r.site_id`

func scanRun(row pgx.Row, extra ...any) (*Run, error) {
	var r Run
	dst := append([]any{&r.ID, &r.JobID, &r.DeviceID, &r.DeviceName, &r.OrganizationID, &r.OrganizationName, &r.SiteID, &r.SiteName, &r.ScriptName,
		&r.Status, &r.CreatedAt, &r.ExpiresAt, &r.SentAt, &r.Deliveries, &r.StartedAt, &r.FinishedAt, &r.ExitCode, &r.Error,
		&r.StdoutTruncated, &r.StderrTruncated, &r.CancelRequested}, extra...)
	if err := row.Scan(dst...); err != nil {
		return nil, err
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
}

// CreateJob runs a library script on devices. Every device must pass every
// check, or nothing runs.
func (s *Service) CreateJob(ctx context.Context, c access.Caller, in JobInput) (*Job, error) {
	f := apperr.Fields{}
	ids := slices.Clone(in.DeviceIDs)
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
		f.Check(in.TimeoutSeconds >= MinTimeout && in.TimeoutSeconds <= MaxTimeout, "timeoutSeconds", "Use 1 second to 4 hours.")
	}
	wait := in.WaitHours
	if wait == 0 {
		wait = DefaultWaitHours
	}
	f.Check(wait >= MinWaitHours && wait <= MaxWaitHours, "waitHours", "Wait 1 hour to 7 days.")
	if in.ScriptID == uuid.Nil {
		f.Add("scriptId", "Choose a script.")
	}
	if err := f.Err(); err != nil {
		return nil, err
	}

	jobID := uuid.New()
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		sc, err := s.getScript(ctx, tx, c, in.ScriptID, false)
		if errors.Is(err, apperr.ErrNotFound) {
			return apperr.Invalid("scriptId", "That script does not exist or you cannot read it.")
		}
		if err != nil {
			return err
		}
		targets, err := s.targets(ctx, tx, c, sc, ids)
		if err != nil {
			return err
		}
		timeout := sc.TimeoutSeconds
		if in.TimeoutSeconds != 0 {
			timeout = in.TimeoutSeconds
		}
		now := s.now()
		expires := now.Add(time.Duration(wait) * time.Hour)
		sum := sha256.Sum256([]byte(sc.Body))
		label := c.Actor.Label
		if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, script_id, script_name, shell, body, body_sha256, args, timeout_seconds,
				expires_at, created_by, created_by_label, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			jobID, sc.ID, sc.Name, sc.Shell, sc.Body, sum[:], args, timeout, expires, nullUUID(c.Actor.ID), truncateRunes(label, 320), now); err != nil {
			return err
		}
		for _, t := range targets {
			var runID uuid.UUID
			if err := tx.QueryRow(ctx, `INSERT INTO job_runs (job_id, organization_id, site_id, device_id, expires_at, created_at)
				VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`, jobID, t.org, t.site, t.id, expires, now).Scan(&runID); err != nil {
				return err
			}
			if err := s.audit.Write(ctx, tx, audit.Event{
				Actor: c.Actor, Action: "device.script_run", Outcome: audit.Success,
				OrganizationID: t.org, SiteID: t.site, DeviceID: t.id, TargetType: "job_run", TargetID: runID.String(),
				Details: map[string]any{
					"device": t.name, "script": sc.Name, "scriptId": sc.ID.String(), "shell": sc.Shell, "sha256": hex.EncodeToString(sum[:]),
					"jobId": jobID.String(), "argCount": len(args), "timeoutSeconds": timeout,
				},
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

// targets resolves and checks the devices of a new job.
func (s *Service) targets(ctx context.Context, tx pgx.Tx, c access.Caller, sc *Script, ids []uuid.UUID) ([]target, error) {
	rows, err := tx.Query(ctx, `SELECT d.id, d.organization_id, d.site_id, d.name, d.platform, d.agent_public_key IS NOT NULL
		FROM devices d WHERE d.id = ANY ($1) ORDER BY lower(d.name), d.id`, ids)
	if err != nil {
		return nil, err
	}
	var found []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.org, &t.site, &t.name, &t.platform, &t.enrolled); err != nil {
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
	org, site := sc.level()
	platforms := agentproto.ShellPlatforms(sc.Shell)
	var forbidden, outside, noAgent, wrongOS []string
	for _, t := range found {
		switch {
		case !c.Can(rbac.PermScriptRun, rbac.Site(t.org, t.site)):
			forbidden = append(forbidden, t.name)
		case !covers(org, site, t.org, t.site):
			outside = append(outside, t.name)
		case !t.enrolled:
			noAgent = append(noAgent, t.name)
		case !slices.Contains(platforms, t.platform):
			wrongOS = append(wrongOS, t.name)
		}
	}
	switch {
	case len(forbidden) > 0:
		return nil, apperr.Invalid("deviceIds", "You cannot run scripts on "+names(forbidden)+".")
	case len(outside) > 0:
		where := "its organization"
		if site != uuid.Nil {
			where = "its site"
		}
		return nil, apperr.Invalid("deviceIds", "This script runs only on devices in "+where+", not on "+names(outside)+".")
	case len(noAgent) > 0:
		return nil, apperr.Invalid("deviceIds", names(noAgent)+" "+pick(len(noAgent), "has", "have")+" no EasyRMM agent to run scripts.")
	case len(wrongOS) > 0:
		os := platformName(platforms)
		return nil, apperr.Invalid("deviceIds", shellName(sc.Shell)+" scripts run on "+os+"; "+names(wrongOS)+" "+pick(len(wrongOS), "is", "are")+" not "+article(os)+" "+os+" device.")
	}
	return found, nil
}

// shellName is how people write a shell's name.
func shellName(shell string) string {
	switch shell {
	case agentproto.ShellPowerShell:
		return "PowerShell"
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
	DeviceID uuid.UUID
	ScriptID uuid.UUID
	// Status is "", "open" (some run has not ended) or "finished".
	Status string
}

const jobColumns = `j.id, j.script_id, j.script_name, j.shell, encode(j.body_sha256, 'hex'), j.args, j.timeout_seconds,
	j.expires_at, j.created_by_label, j.created_at`

func scanJob(row pgx.Row, extra ...any) (*Job, error) {
	var j Job
	dst := append([]any{&j.ID, &j.ScriptID, &j.ScriptName, &j.Shell, &j.SHA256, &j.Args, &j.TimeoutSeconds,
		&j.ExpiresAt, &j.CreatedBy, &j.CreatedAt}, extra...)
	if err := row.Scan(dst...); err != nil {
		return nil, err
	}
	if j.Args == nil {
		j.Args = []string{}
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
			ORDER BY j.created_at DESC, j.id LIMIT $4`,
			nullUUID(q.DeviceID), nullUUID(q.ScriptID), q.Status, MaxList)
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
		j, err = scanJob(tx.QueryRow(ctx, `SELECT `+jobColumns+`, j.body FROM jobs j WHERE j.id = $1`, id), &body)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		j.Body = body
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
}

// ListRuns returns a device's newest runs.
func (s *Service) ListRuns(ctx context.Context, c access.Caller, q RunQuery) ([]*Run, error) {
	if q.DeviceID == uuid.Nil {
		return nil, apperr.Invalid("deviceId", "Choose a device.")
	}
	out := []*Run{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+runColumns+runFrom+` WHERE r.device_id = $1 ORDER BY r.created_at DESC, r.id LIMIT $2`,
			q.DeviceID, MaxList)
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

// GetRun returns a run with its output and its job.
func (s *Service) GetRun(ctx context.Context, c access.Caller, id uuid.UUID) (*Run, error) {
	var r *Run
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var stdout, stderr, body string
		var err error
		job := &Job{}
		r, err = scanRun(tx.QueryRow(ctx, `SELECT `+runColumns+`, r.stdout, r.stderr, `+jobColumns+`, j.body`+runFrom+` WHERE r.id = $1`, id),
			&stdout, &stderr, &job.ID, &job.ScriptID, &job.ScriptName, &job.Shell, &job.SHA256, &job.Args, &job.TimeoutSeconds,
			&job.ExpiresAt, &job.CreatedBy, &job.CreatedAt, &body)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		if job.Args == nil {
			job.Args = []string{}
		}
		job.Body = body
		r.Stdout, r.Stderr, r.Job = &stdout, &stderr, job
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermJobView, rbac.Site(r.OrganizationID, r.SiteID)) {
		return nil, apperr.NotFound()
	}
	s.decorateRun(c, r)
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
