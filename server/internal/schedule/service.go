package schedule

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/notify"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Task states.
const (
	StateActive    = "active"
	StatePaused    = "paused"
	StateCancelled = "cancelled"
	StateCompleted = "completed"
)

// What a task does when its time passed while the server was down.
const (
	RuleSkip    = "skip"
	RuleRunASAP = "run_asap"
)

// Run states.
const (
	RunPending   = "pending"
	RunRunning   = "running"
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
	RunSkipped   = "skipped"
)

// MaxStaggerMinutes bounds a task's stagger.
const MaxStaggerMinutes = 1440

// Tick is how often the scheduler looks for due tasks. An occurrence found
// later than Grace past its time counts as missed.
const (
	Tick  = 30 * time.Second
	Grace = 5 * time.Minute
)

// Scripts is what the scheduler needs of the script library and jobs.
type Scripts interface {
	GetScript(ctx context.Context, c access.Caller, id uuid.UUID) (*jobs.Script, error)
	CreateJob(ctx context.Context, c access.Caller, in jobs.JobInput) (*jobs.Job, error)
}

// Principals loads a user's permissions as they are now.
type Principals interface {
	LoadPrincipal(ctx context.Context, userID uuid.UUID) (*rbac.Principal, error)
}

// Targets picks the devices a task runs on, at each run: the listed
// devices, or when none are listed every device of the task's site (or
// organization) the script can run on.
type Targets struct {
	DeviceIDs []uuid.UUID `json:"deviceIds"`
}

// Task is a scheduled script job.
type Task struct {
	ID               uuid.UUID  `json:"id"`
	OrganizationID   uuid.UUID  `json:"organizationId"`
	OrganizationName string     `json:"organizationName"`
	SiteID           *uuid.UUID `json:"siteId"`
	SiteName         string     `json:"siteName"`
	Name             string     `json:"name"`
	Schedule         Schedule   `json:"schedule"`
	ScriptID         uuid.UUID  `json:"scriptId"`
	ScriptName       string     `json:"scriptName"`
	ScriptSHA256     string     `json:"scriptSha256"`
	// ScriptChanged says the library's script is no longer the pinned one:
	// runs fail until the task is saved again with Repin.
	ScriptChanged bool     `json:"scriptChanged"`
	ScriptArgs    []string `json:"scriptArgs"`
	Targets       Targets  `json:"targets"`
	Timezone      string   `json:"timezone"`
	MissedRunRule string   `json:"missedRunRule"`
	WaitHours     int      `json:"waitHours"`
	// WindowID is the maintenance window the task is held to: it fires only
	// while the window is open. StaggerMinutes spreads a site's devices over
	// that long; OnlyIfOnline leaves offline devices out.
	WindowID       *uuid.UUID `json:"windowId"`
	WindowName     string     `json:"windowName"`
	StaggerMinutes int        `json:"staggerMinutes"`
	OnlyIfOnline   bool       `json:"onlyIfOnline"`
	OwnerID        uuid.UUID  `json:"ownerId"`
	OwnerEmail     string     `json:"ownerEmail"`
	State          string     `json:"state"`
	NextRunAt      *time.Time `json:"nextRunAt"`
	LastRunAt      *time.Time `json:"lastRunAt"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      time.Time  `json:"updatedAt"`
	CanEdit        bool       `json:"canEdit"`
}

// Run is one occurrence of a task.
type Run struct {
	ID            uuid.UUID   `json:"id"`
	TaskID        uuid.UUID   `json:"taskId"`
	OccurrenceKey string      `json:"occurrenceKey"`
	ScheduledFor  time.Time   `json:"scheduledFor"`
	State         string      `json:"state"`
	Detail        string      `json:"detail"`
	StartedAt     *time.Time  `json:"startedAt"`
	CompletedAt   *time.Time  `json:"completedAt"`
	JobIDs        []uuid.UUID `json:"jobIds"`
}

// Service keeps scheduled tasks and fires them.
type Service struct {
	db         *database.DB
	audit      *audit.Logger
	scripts    Scripts
	principals Principals
	scopeOf    func(*rbac.Principal) database.Scope
	log        *slog.Logger
	now        func() time.Time
}

// New returns a Service. scopeOf derives a principal's database scope
// (auth.DataScope).
func New(db *database.DB, auditLog *audit.Logger, scripts Scripts, principals Principals, scopeOf func(*rbac.Principal) database.Scope, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, scripts: scripts, principals: principals, scopeOf: scopeOf, log: log, now: time.Now}
}

const taskSelect = `SELECT a.id, a.organization_id, o.name, a.site_id, coalesce(si.name, ''), a.name, a.schedule,
	a.script_id, coalesce(sc.name, ''), a.script_sha256,
	coalesce(encode(sha256(convert_to(sc.body, 'UTF8')), 'hex') <> a.script_sha256, true),
	a.script_args, a.target_query, coalesce(si.timezone, o.timezone), a.missed_run_rule, a.wait_hours,
	a.window_id, coalesce(mw.name, ''), a.stagger_minutes, a.only_if_online,
	a.owner_id, coalesce(u.email, ''), a.state, a.next_run_at, a.last_run_at, a.created_at, a.updated_at
	FROM automations a JOIN organizations o ON o.id = a.organization_id
	LEFT JOIN sites si ON si.id = a.site_id
	LEFT JOIN site_maintenance_windows mw ON mw.id = a.window_id
	LEFT JOIN scripts sc ON sc.id = a.script_id
	LEFT JOIN users u ON u.id = a.owner_id`

func scanTask(row pgx.Row) (*Task, error) {
	var t Task
	if err := row.Scan(&t.ID, &t.OrganizationID, &t.OrganizationName, &t.SiteID, &t.SiteName, &t.Name, &t.Schedule,
		&t.ScriptID, &t.ScriptName, &t.ScriptSHA256, &t.ScriptChanged, &t.ScriptArgs, &t.Targets, &t.Timezone,
		&t.MissedRunRule, &t.WaitHours, &t.WindowID, &t.WindowName, &t.StaggerMinutes, &t.OnlyIfOnline, &t.OwnerID, &t.OwnerEmail, &t.State, &t.NextRunAt, &t.LastRunAt,
		&t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	if t.ScriptArgs == nil {
		t.ScriptArgs = []string{}
	}
	if t.Targets.DeviceIDs == nil {
		t.Targets.DeviceIDs = []uuid.UUID{}
	}
	return &t, nil
}

func (t *Task) resource() rbac.Resource {
	if t.SiteID != nil {
		return rbac.Site(t.OrganizationID, *t.SiteID)
	}
	return rbac.Org(t.OrganizationID)
}

func (t *Task) loc() *time.Location {
	loc, err := time.LoadLocation(t.Timezone)
	if err != nil {
		return time.UTC
	}
	return loc
}

func (s *Service) decorate(c access.Caller, t *Task) {
	t.CanEdit = c.Can(rbac.PermScriptRun, t.resource())
}

func canSee(c access.Caller, t *Task) bool {
	return c.Can(rbac.PermScriptRun, t.resource()) || c.Can(rbac.PermJobView, t.resource())
}

// Input creates a task.
type Input struct {
	Name           string      `json:"name"`
	OrganizationID uuid.UUID   `json:"organizationId"`
	SiteID         *uuid.UUID  `json:"siteId"`
	ScriptID       uuid.UUID   `json:"scriptId"`
	ScriptArgs     []string    `json:"scriptArgs"`
	DeviceIDs      []uuid.UUID `json:"deviceIds"`
	Schedule       Schedule    `json:"schedule"`
	MissedRunRule  string      `json:"missedRunRule"`
	WaitHours      int         `json:"waitHours"`
	WindowID       *uuid.UUID  `json:"windowId"`
	StaggerMinutes int         `json:"staggerMinutes"`
	OnlyIfOnline   bool        `json:"onlyIfOnline"`
}

// Patch edits a task; nil fields stay. Saving makes the editor the owner,
// whose permissions then back every run.
type Patch struct {
	Name          *string      `json:"name"`
	ScriptID      *uuid.UUID   `json:"scriptId"`
	ScriptArgs    *[]string    `json:"scriptArgs"`
	DeviceIDs     *[]uuid.UUID `json:"deviceIds"`
	Schedule      *Schedule    `json:"schedule"`
	MissedRunRule *string      `json:"missedRunRule"`
	WaitHours     *int         `json:"waitHours"`
	// WindowID holds the task to a window; ClearWindow lifts the hold.
	WindowID       *uuid.UUID `json:"windowId"`
	ClearWindow    bool       `json:"clearWindow"`
	StaggerMinutes *int       `json:"staggerMinutes"`
	OnlyIfOnline   *bool      `json:"onlyIfOnline"`
	// Repin adopts the library script as it is now.
	Repin bool `json:"repin"`
}

func checkStagger(f apperr.Fields, minutes *int) {
	if minutes != nil {
		f.Check(*minutes >= 0 && *minutes <= MaxStaggerMinutes, "staggerMinutes", fmt.Sprintf("Stagger from 0 to %d minutes.", MaxStaggerMinutes))
	}
}

// checkWindow says whether a task may be held to the window: it must be in
// the task's organization and site, allow tasks, and be at least as long as
// the stagger.
func checkWindow(ctx context.Context, tx pgx.Tx, now time.Time, org uuid.UUID, site, window *uuid.UUID, stagger int) error {
	if window == nil {
		return nil
	}
	w, err := notify.LoadTaskWindow(ctx, tx, *window, now)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return apperr.Invalid("windowId", "That maintenance window does not exist.")
	case err != nil:
		return err
	case w.OrganizationID != org || (site != nil && w.SiteID != *site):
		return apperr.Invalid("windowId", "That window belongs to another organization or site.")
	case !notify.AllowsTasks(w.Purpose):
		return apperr.Invalid("windowId", "That window does not allow tasks; set its purpose to tasks or both.")
	case stagger > w.LengthMinutes:
		return apperr.Invalid("staggerMinutes", "The stagger is longer than the window.")
	}
	return nil
}

func checkCommon(f apperr.Fields, name *string, args *[]string, rule *string, wait *int) {
	if name != nil {
		*name = strings.TrimSpace(*name)
		f.Check(len(*name) >= 1 && len(*name) <= 200, "name", "Name the task in 1 to 200 characters.")
	}
	if args != nil {
		f.Check(len(*args) <= jobs.MaxArgs, "scriptArgs", fmt.Sprintf("Use at most %d arguments.", jobs.MaxArgs))
		for _, a := range *args {
			if len(a) > jobs.MaxArgBytes || strings.ContainsRune(a, 0) {
				f.Add("scriptArgs", "An argument is too long or holds a NUL character.")
				break
			}
		}
	}
	if rule != nil {
		f.Check(*rule == RuleSkip || *rule == RuleRunASAP, "missedRunRule", "Choose skip or run as soon as possible.")
	}
	if wait != nil {
		f.Check(*wait >= jobs.MinWaitHours && *wait <= jobs.MaxWaitHours, "waitHours", "Wait 1 hour to 7 days.")
	}
}

func (s *Service) auditTx(ctx context.Context, tx pgx.Tx, actor audit.Actor, action string, t *Task, outcome audit.Outcome, details map[string]any) error {
	e := audit.Event{Actor: actor, Action: action, OrganizationID: t.OrganizationID, TargetType: "automation",
		TargetID: t.ID.String(), Outcome: outcome, Details: details}
	if t.SiteID != nil {
		e.SiteID = *t.SiteID
	}
	return s.audit.Write(ctx, tx, e)
}

func details(t *Task) map[string]any {
	return map[string]any{"name": t.Name, "script": t.ScriptName, "scriptId": t.ScriptID.String(), "scriptSha256": t.ScriptSHA256,
		"schedule": t.Schedule.Kind, "timezone": t.Timezone, "missedRunRule": t.MissedRunRule,
		"window": t.WindowName, "staggerMinutes": t.StaggerMinutes, "onlyIfOnline": t.OnlyIfOnline}
}

// pin reads the library script for the caller and checks it can run where
// the task is.
func (s *Service) pin(ctx context.Context, c access.Caller, id, org uuid.UUID, site *uuid.UUID) (*jobs.Script, error) {
	sc, err := s.scripts.GetScript(ctx, c, id)
	if errors.Is(err, apperr.ErrNotFound) {
		return nil, apperr.Invalid("scriptId", "That script does not exist or you cannot read it.")
	}
	if err != nil {
		return nil, err
	}
	if (sc.OrganizationID != nil && *sc.OrganizationID != org) ||
		(sc.SiteID != nil && (site == nil || *sc.SiteID != *site)) {
		return nil, apperr.Invalid("scriptId", "That script belongs to another organization or site.")
	}
	return sc, nil
}

// Create saves a task. The caller needs to run scripts where it is.
func (s *Service) Create(ctx context.Context, c access.Caller, in Input) (*Task, error) {
	if c.Principal == nil {
		return nil, apperr.Forbidden()
	}
	f := apperr.Fields{}
	if in.MissedRunRule == "" {
		in.MissedRunRule = RuleSkip
	}
	if in.WaitHours == 0 {
		in.WaitHours = jobs.DefaultWaitHours
	}
	checkCommon(f, &in.Name, &in.ScriptArgs, &in.MissedRunRule, &in.WaitHours)
	checkStagger(f, &in.StaggerMinutes)
	f.Check(in.OrganizationID != uuid.Nil, "organizationId", "Choose an organization.")
	f.Check(in.ScriptID != uuid.Nil, "scriptId", "Choose a script.")
	f.Check(len(in.DeviceIDs) <= jobs.MaxDevices, "deviceIds", "Choose fewer devices, or none for all.")
	now := s.now()
	sched, err := in.Schedule.Clean(now)
	if err != nil {
		return nil, err
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	res := rbac.Org(in.OrganizationID)
	if in.SiteID != nil {
		res = rbac.Site(in.OrganizationID, *in.SiteID)
	}
	if err := c.Require(rbac.PermScriptRun, res); err != nil {
		return nil, err
	}
	sc, err := s.pin(ctx, c, in.ScriptID, in.OrganizationID, in.SiteID)
	if err != nil {
		return nil, err
	}
	if in.ScriptArgs == nil {
		in.ScriptArgs = []string{}
	}
	if in.DeviceIDs == nil {
		in.DeviceIDs = []uuid.UUID{}
	}
	var out *Task
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var tz string
		q, args := `SELECT timezone FROM organizations WHERE id = $1`, []any{in.OrganizationID}
		if in.SiteID != nil {
			q, args = `SELECT timezone FROM sites WHERE id = $2 AND organization_id = $1`, append(args, *in.SiteID)
		}
		if err := tx.QueryRow(ctx, q, args...).Scan(&tz); errors.Is(err, pgx.ErrNoRows) {
			return apperr.Invalid("organizationId", "That organization or site does not exist.")
		} else if err != nil {
			return err
		}
		loc, lerr := time.LoadLocation(tz)
		if lerr != nil {
			loc = time.UTC
		}
		next, ok := sched.Next(loc, now)
		if !ok {
			return apperr.Invalid("schedule", "That time has already passed.")
		}
		if err := checkWindow(ctx, tx, now, in.OrganizationID, in.SiteID, in.WindowID, in.StaggerMinutes); err != nil {
			return err
		}
		var id uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO automations (organization_id, site_id, name, schedule, script_id, script_sha256,
			script_args, target_query, timezone, missed_run_rule, wait_hours, owner_id, next_run_at, window_id, stagger_minutes, only_if_online)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING id`,
			in.OrganizationID, in.SiteID, in.Name, sched, sc.ID, sc.SHA256, in.ScriptArgs, Targets{DeviceIDs: in.DeviceIDs}, tz,
			in.MissedRunRule, in.WaitHours, c.Actor.ID, next, in.WindowID, in.StaggerMinutes, in.OnlyIfOnline).Scan(&id); err != nil {
			return err
		}
		t, err := scanTask(tx.QueryRow(ctx, taskSelect+` WHERE a.id = $1`, id))
		if err != nil {
			return err
		}
		out = t
		return s.auditTx(ctx, tx, c.Actor, "automation.create", t, audit.Success, details(t))
	})
	if err != nil {
		return nil, err
	}
	s.decorate(c, out)
	return out, nil
}

// lock reads a task for change, if the caller may change it.
func (s *Service) lock(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID) (*Task, error) {
	t, err := scanTask(tx.QueryRow(ctx, taskSelect+` WHERE a.id = $1 FOR UPDATE OF a`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if !canSee(c, t) {
		return nil, apperr.NotFound()
	}
	if err := c.Require(rbac.PermScriptRun, t.resource()); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Service) reload(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID) (*Task, error) {
	t, err := scanTask(tx.QueryRow(ctx, taskSelect+` WHERE a.id = $1`, id))
	if err != nil {
		return nil, err
	}
	s.decorate(c, t)
	return t, nil
}

var errFinished = apperr.Conflict("task_finished", "That task is cancelled or has finished; create a new one.")

// Update edits a task.
func (s *Service) Update(ctx context.Context, c access.Caller, id uuid.UUID, p Patch) (*Task, error) {
	f := apperr.Fields{}
	checkCommon(f, p.Name, p.ScriptArgs, p.MissedRunRule, p.WaitHours)
	checkStagger(f, p.StaggerMinutes)
	if p.DeviceIDs != nil {
		f.Check(len(*p.DeviceIDs) <= jobs.MaxDevices, "deviceIds", "Choose fewer devices, or none for all.")
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	var out *Task
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		t, err := s.lock(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if t.State == StateCancelled || t.State == StateCompleted {
			return errFinished
		}
		if p.Name != nil {
			t.Name = *p.Name
		}
		if p.ScriptArgs != nil {
			t.ScriptArgs = *p.ScriptArgs
		}
		if p.DeviceIDs != nil {
			t.Targets.DeviceIDs = *p.DeviceIDs
		}
		if p.MissedRunRule != nil {
			t.MissedRunRule = *p.MissedRunRule
		}
		if p.WaitHours != nil {
			t.WaitHours = *p.WaitHours
		}
		if p.ClearWindow {
			t.WindowID = nil
		} else if p.WindowID != nil {
			t.WindowID = p.WindowID
		}
		if p.StaggerMinutes != nil {
			t.StaggerMinutes = *p.StaggerMinutes
		}
		if p.OnlyIfOnline != nil {
			t.OnlyIfOnline = *p.OnlyIfOnline
		}
		if err := checkWindow(ctx, tx, s.now(), t.OrganizationID, t.SiteID, t.WindowID, t.StaggerMinutes); err != nil {
			return err
		}
		if p.ScriptID != nil || p.Repin {
			sid := t.ScriptID
			if p.ScriptID != nil {
				sid = *p.ScriptID
			}
			sc, err := s.pin(ctx, c, sid, t.OrganizationID, t.SiteID)
			if err != nil {
				return err
			}
			t.ScriptID, t.ScriptSHA256 = sc.ID, sc.SHA256
		}
		now := s.now()
		if p.Schedule != nil {
			sched := *p.Schedule
			if sched.Kind == KindInterval && t.Schedule.Kind == KindInterval && sched.Anchor == nil &&
				sched.EveryMinutes == t.Schedule.EveryMinutes {
				sched.Anchor = t.Schedule.Anchor
			}
			if t.Schedule, err = sched.Clean(now); err != nil {
				return err
			}
		}
		var next *time.Time
		if t.State == StateActive {
			n, ok := t.Schedule.Next(t.loc(), now)
			if !ok {
				return apperr.Invalid("schedule", "That time has already passed.")
			}
			next = &n
		}
		if _, err := tx.Exec(ctx, `UPDATE automations SET name = $2, schedule = $3, script_id = $4, script_sha256 = $5,
			script_args = $6, target_query = $7, missed_run_rule = $8, wait_hours = $9, owner_id = $10, next_run_at = $11,
			window_id = $12, stagger_minutes = $13, only_if_online = $14
			WHERE id = $1`, id, t.Name, t.Schedule, t.ScriptID, t.ScriptSHA256, t.ScriptArgs, t.Targets,
			t.MissedRunRule, t.WaitHours, c.Actor.ID, next, t.WindowID, t.StaggerMinutes, t.OnlyIfOnline); err != nil {
			return err
		}
		if out, err = s.reload(ctx, tx, c, id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, c.Actor, "automation.update", out, audit.Success, details(out))
	})
	return out, err
}

// Pause holds a task.
func (s *Service) Pause(ctx context.Context, c access.Caller, id uuid.UUID) (*Task, error) {
	return s.setState(ctx, c, id, "automation.pause")
}

// Resume continues a paused task from its next occurrence, with no catch-up.
func (s *Service) Resume(ctx context.Context, c access.Caller, id uuid.UUID) (*Task, error) {
	return s.setState(ctx, c, id, "automation.resume")
}

// Cancel ends a task; its history stays.
func (s *Service) Cancel(ctx context.Context, c access.Caller, id uuid.UUID) (*Task, error) {
	return s.setState(ctx, c, id, "automation.cancel")
}

func (s *Service) setState(ctx context.Context, c access.Caller, id uuid.UUID, action string) (*Task, error) {
	var out *Task
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		t, err := s.lock(ctx, tx, c, id)
		if err != nil {
			return err
		}
		var state string
		var next *time.Time
		switch action {
		case "automation.pause":
			if t.State != StateActive {
				return apperr.Conflict("not_active", "Only an active task can be paused.")
			}
			state = StatePaused
		case "automation.resume":
			if t.State != StatePaused {
				return apperr.Conflict("not_paused", "Only a paused task can be resumed.")
			}
			n, ok := t.Schedule.Next(t.loc(), s.now())
			if !ok {
				return apperr.Invalid("schedule", "The one-time run has passed; edit the date first.")
			}
			state, next = StateActive, &n
		default:
			if t.State == StateCancelled || t.State == StateCompleted {
				return errFinished
			}
			state = StateCancelled
		}
		owner := t.OwnerID
		if state == StateActive {
			owner = c.Actor.ID
		}
		if _, err := tx.Exec(ctx, `UPDATE automations SET state = $2, next_run_at = $3, owner_id = $4 WHERE id = $1`,
			id, state, next, owner); err != nil {
			return err
		}
		if out, err = s.reload(ctx, tx, c, id); err != nil {
			return err
		}
		return s.auditTx(ctx, tx, c.Actor, action, out, audit.Success, details(out))
	})
	return out, err
}

// Query filters the task list.
type Query struct {
	OrganizationID uuid.UUID
	SiteID         uuid.UUID
	State          string
}

// MaxTasks bounds a list.
const MaxTasks = 1000

// List returns the tasks the caller can read, by name.
func (s *Service) List(ctx context.Context, c access.Caller, q Query) ([]*Task, error) {
	return s.list(ctx, c, q, `ORDER BY lower(a.name), a.id`, MaxTasks)
}

// Upcoming returns active tasks in the order they fire next.
func (s *Service) Upcoming(ctx context.Context, c access.Caller, limit int) ([]*Task, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	return s.list(ctx, c, Query{State: StateActive}, `ORDER BY a.next_run_at, a.id`, limit)
}

func (s *Service) list(ctx context.Context, c access.Caller, q Query, order string, limit int) ([]*Task, error) {
	out := []*Task{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, taskSelect+` WHERE ($1 = '00000000-0000-0000-0000-000000000000'::uuid OR a.organization_id = $1)
			AND ($2 = '00000000-0000-0000-0000-000000000000'::uuid OR a.site_id = $2) AND ($3 = '' OR a.state = $3) `+order+` LIMIT $4`,
			q.OrganizationID, q.SiteID, q.State, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanTask(rows)
			if err != nil {
				return err
			}
			if canSee(c, t) {
				s.decorate(c, t)
				out = append(out, t)
			}
		}
		return rows.Err()
	})
	return out, err
}

// Get returns one task.
func (s *Service) Get(ctx context.Context, c access.Caller, id uuid.UUID) (*Task, error) {
	var t *Task
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		t, err = scanTask(tx.QueryRow(ctx, taskSelect+` WHERE a.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if !canSee(c, t) {
		return nil, apperr.NotFound()
	}
	s.decorate(c, t)
	return t, nil
}

// History returns a task's runs, newest first.
func (s *Service) History(ctx context.Context, c access.Caller, id uuid.UUID, limit int) ([]*Run, error) {
	if _, err := s.Get(ctx, c, id); err != nil {
		return nil, err
	}
	if limit < 1 || limit > 500 {
		limit = 100
	}
	out := []*Run{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, automation_id, occurrence_key, scheduled_for, state, detail, started_at, completed_at, job_ids
			FROM automation_runs WHERE automation_id = $1 ORDER BY scheduled_for DESC LIMIT $2`, id, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r Run
			if err := rows.Scan(&r.ID, &r.TaskID, &r.OccurrenceKey, &r.ScheduledFor, &r.State, &r.Detail, &r.StartedAt, &r.CompletedAt, &r.JobIDs); err != nil {
				return err
			}
			if r.JobIDs == nil {
				r.JobIDs = []uuid.UUID{}
			}
			out = append(out, &r)
		}
		return rows.Err()
	})
	return out, err
}
