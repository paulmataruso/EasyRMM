package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// KindWinmod is the kind of a Windows management module's job (ADR-0073):
// one kind for every module, with the module and action in the job's winmod
// record. Such jobs are hidden from the Jobs list.
const KindWinmod = "winmod"

// How long a winmod job waits for its computer: a job that carries a secret
// is never held longer than the secret's own life.
const (
	winmodWait       = 30 * time.Minute
	winmodSecretWait = 10 * time.Minute
)

// ModuleGate says whether a module may be used for a site: the toggle and
// the development scope (modules.Service.Allowed).
type ModuleGate interface {
	Allowed(ctx context.Context, org, site uuid.UUID, m modules.Module) bool
}

// SetWinmod gives the service the catalog of actions, the module gate and
// the sealer for secrets. Without them no winmod job is made.
func (s *Service) SetWinmod(c *winmod.Catalog, g ModuleGate, sealer *secrets.Sealer) {
	s.catalog, s.gate, s.sealer = c, g, sealer
}

// winmodRecord is a winmod job's record (jobs.winmod): what ran, without
// any secret value.
type winmodRecord struct {
	Module       string `json:"module"`
	Action       string `json:"action"`
	Version      int    `json:"version"`
	ScriptSHA256 string `json:"scriptSha256"`
	// Secrets names the parameters sealed apart and placed at delivery.
	Secrets []string `json:"secrets,omitempty"`
	// Subject is the confirmed subject, for destructive actions.
	Subject     string `json:"subject,omitempty"`
	KeepSeconds int    `json:"keepSeconds"`
}

// WinmodInput asks for one action of a module on one device.
type WinmodInput struct {
	DeviceID uuid.UUID `json:"-"`
	// Action is "<module>.<action>".
	Action string          `json:"-"`
	Params json.RawMessage `json:"params"`
	// Confirm is "<action>:<subject>", for a destructive action.
	Confirm string `json:"confirm"`
}

// WinmodRun is what a new action answers: the run to follow.
type WinmodRun struct {
	JobID     uuid.UUID `json:"jobId"`
	RunID     uuid.UUID `json:"runId"`
	Action    string    `json:"action"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// errWinmodPin is a script that does not match the hash its job pinned.
var errWinmodPin = errors.New("jobs: a winmod script does not match its pinned hash")

// errSecretGone is a secret already delivered, or expired.
var errSecretGone = errors.New("jobs: a winmod secret is not there to deliver")

// RunWinmod starts one action of a Windows management module on one device
// (ADR-0073). It checks, in this order: the action is in the catalog; its
// parameters match its schema; the caller holds the action's permission on
// the device; the module is on for the device's site and its organization is
// in the development scope; a destructive action's confirmation; and, for a
// destructive or credential action, a step-up. Then it writes the job and
// its audit row, and seals any secret for delivery.
func (s *Service) RunWinmod(ctx context.Context, c access.Caller, in WinmodInput) (*WinmodRun, error) {
	if s.catalog == nil || s.gate == nil {
		return nil, apperr.Unavailable("winmod_unavailable", "Windows modules are not available on this server.")
	}
	a, ok := s.catalog.Lookup(in.Action)
	if !ok {
		return nil, apperr.NotFound()
	}
	chk, err := a.Validate(in.Params)
	if err != nil {
		return nil, err
	}
	if a.Destructive {
		f := apperr.Fields{}
		f.Check(in.Confirm == a.ConfirmText(chk.Subject), "confirm", "Confirm the action by sending \""+a.ConfirmText(chk.Subject)+"\".")
		if err := f.Err(); err != nil {
			return nil, err
		}
	}
	if len(chk.Secrets) > 0 && s.sealer == nil {
		return nil, apperr.Unavailable("winmod_unavailable", "Secrets cannot be sealed on this server.")
	}
	if a.NeedsStepUp() && s.stepUp == nil {
		return nil, apperr.Conflict("step_up_required", "This action needs step-up authentication (ADR-0055), which is not available yet.")
	}
	rec := winmodRecord{Module: string(a.Module), Action: a.Name, Version: a.Version, ScriptSHA256: agentproto.HashScript(a.Script),
		Subject: chk.Subject, KeepSeconds: int(a.Keep.Seconds())}
	for name := range chk.Secrets {
		rec.Secrets = append(rec.Secrets, name)
	}
	slices.Sort(rec.Secrets)
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	ttl := winmodWait
	if len(rec.Secrets) > 0 {
		ttl = winmodSecretWait
	}
	sp := &spec{
		kind: KindWinmod, name: a.Label, shell: a.ShellName(), body: a.Script, args: []string{}, params: chk.Params,
		timeout: a.Timeout, auditAction: "winmod." + a.Name, winmod: recJSON, ttl: ttl,
		details: map[string]any{"module": string(a.Module), "action": a.Name, "version": a.Version, "params": chk.Audit,
			"sensitive": a.Sensitive, "destructive": a.Destructive, "confirmed": a.Destructive, "stepUp": a.NeedsStepUp()},
		inserted: func(ctx context.Context, tx pgx.Tx, jobID uuid.UUID, expires time.Time) error {
			for name, value := range chk.Secrets {
				sealed, err := s.sealer.Seal([]byte(value), winmodAAD(jobID, name))
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO winmod_job_secrets (job_id, name, sealed, expires_at) VALUES ($1, $2, $3, $4)`,
					jobID, name, sealed, expires); err != nil {
					return err
				}
			}
			return nil
		},
	}
	r := rule{perm: a.Permission, verb: "use " + a.Label, platforms: agentproto.ShellPlatforms(a.ShellName()), runsOn: "Module actions run on", what: "module actions"}
	job, err := s.create(ctx, c, []uuid.UUID{in.DeviceID}, 1, sp, func(ctx context.Context, tx pgx.Tx) ([]target, error) {
		ts, err := s.targets(ctx, tx, c, []uuid.UUID{in.DeviceID}, r)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			// A module that is off, or an organization outside the
			// development scope, is not found (ADR-0073's 404 rule).
			if !s.gate.Allowed(ctx, t.org, t.site, a.Module) {
				return nil, apperr.NotFound()
			}
		}
		if a.NeedsStepUp() {
			return ts, s.stepUp.VerifyStepUp(ctx)
		}
		return ts, nil
	})
	if err != nil {
		return nil, err
	}
	if len(job.Runs) != 1 {
		return nil, fmt.Errorf("jobs: a winmod job has %d runs", len(job.Runs))
	}
	return &WinmodRun{JobID: job.ID, RunID: job.Runs[0].ID, Action: a.Name, Status: job.Runs[0].Status, ExpiresAt: job.ExpiresAt}, nil
}

func winmodAAD(job uuid.UUID, name string) []byte {
	return []byte("easyrmm:winmod:" + job.String() + ":" + name)
}

// winmodDeliver is what a winmod job needs at delivery: the script must be
// the one the job pinned, and each secret is unsealed, deleted and placed
// in the params for this one delivery. A secret that is already gone fails
// the delivery: a password is never held waiting.
func (s *Service) winmodDeliver(ctx context.Context, tx pgx.Tx, jobID uuid.UUID, p *agentproto.JobPayload, rec json.RawMessage) error {
	var m winmodRecord
	if err := json.Unmarshal(rec, &m); err != nil {
		return err
	}
	if agentproto.HashScript(p.Script) != m.ScriptSHA256 {
		return errWinmodPin
	}
	if len(m.Secrets) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `DELETE FROM winmod_job_secrets WHERE job_id = $1 AND expires_at > now() RETURNING name, sealed`, jobID)
	if err != nil {
		return err
	}
	defer rows.Close()
	values := map[string]any{}
	for rows.Next() {
		var name, sealed string
		if err := rows.Scan(&name, &sealed); err != nil {
			return err
		}
		if s.sealer == nil {
			return errSecretGone
		}
		v, err := s.sealer.Open(sealed, winmodAAD(jobID, name))
		if err != nil {
			return err
		}
		values[name] = string(v)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(values) != len(m.Secrets) {
		return errSecretGone
	}
	merged := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(p.Params))
	dec.UseNumber()
	if err := dec.Decode(&merged); err != nil {
		return err
	}
	for k, v := range values {
		merged[k] = v
	}
	out, err := winmod.MarshalParams(merged)
	if err != nil {
		return err
	}
	p.Params = out
	return nil
}

// refuseDelivery ends a run the server will not send, with the reason.
func refuseDelivery(ctx context.Context, tx pgx.Tx, run uuid.UUID, status, reason string) error {
	_, err := tx.Exec(ctx, `UPDATE job_runs SET status = $2, finished_at = now(), error = $3 WHERE id = $1`, run, status, reason)
	return err
}

// scrubOutput empties a winmod run's raw output without marking it removed:
// the typed result stands for it.
const scrubOutput = `stdout = '', stderr = '', stdout_truncated = false, stderr_truncated = false, output_stored_at = NULL`

// recordWinmod keeps what a finished winmod run reported: the typed result,
// not the text. A job that is not a winmod job is left alone (handled is
// false). A result that is not one valid line of the sent version and
// schema fails the run; the raw output stays for job.view_sensitive. A job
// that held a secret keeps no raw output at all, as the secret's value is
// unknown here to be removed from it.
func (s *Service) recordWinmod(ctx context.Context, tx pgx.Tx, device, run uuid.UUID, status, stdout string) (handled bool, err error) {
	var (
		kind      string
		rec       []byte
		org, site uuid.UUID
		jobID     uuid.UUID
		params    []byte
	)
	if err := tx.QueryRow(ctx, `SELECT j.kind, coalesce(j.winmod, 'null'::jsonb), r.organization_id, r.site_id, j.id, coalesce(j.params, 'null'::jsonb)
		FROM job_runs r JOIN jobs j ON j.id = r.job_id WHERE r.id = $1`, run).Scan(&kind, &rec, &org, &site, &jobID, &params); err != nil {
		return false, err
	}
	if kind != KindWinmod {
		return false, nil
	}
	var m winmodRecord
	if err := json.Unmarshal(rec, &m); err != nil {
		return true, err
	}
	hadSecret := len(m.Secrets) > 0
	const generic = "The action did not finish; its output is not kept because the request held a secret."
	audited := func(ok bool, count int, code string) error {
		d := map[string]any{"module": m.Module, "action": m.Action, "version": m.Version, "ok": ok, "count": count}
		if code != "" {
			d["error"] = code
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: audit.SystemActor("winmod"), Action: "winmod." + m.Action + ".result", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, DeviceID: device, TargetType: "job_run", TargetID: run.String(), Details: d,
		})
	}
	fail := func(msg, code string) (bool, error) {
		if hadSecret {
			msg = generic
			if _, err := tx.Exec(ctx, `UPDATE job_runs SET `+scrubOutput+` WHERE id = $1`, run); err != nil {
				return true, err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE job_runs SET status = 'failed', error = $2 WHERE id = $1`, run, truncateRunes(msg, agentproto.MaxJobError)); err != nil {
			return true, err
		}
		return true, audited(false, 0, code)
	}
	if status != StatusSucceeded {
		if hadSecret {
			if _, err := tx.Exec(ctx, `UPDATE job_runs SET `+scrubOutput+`, error = CASE WHEN error <> '' THEN $2 ELSE error END WHERE id = $1`, run, generic); err != nil {
				return true, err
			}
		}
		return true, nil
	}
	var a winmod.Action
	ok := false
	if s.catalog != nil {
		a, ok = s.catalog.Lookup(m.Action)
	}
	if !ok || a.Version != m.Version {
		return fail("The server no longer has the version of the action that was sent.", "unknown_action")
	}
	res, err := a.ParseResult(stdout)
	if err != nil {
		s.log.Warn("jobs: a winmod result was refused", "run", run, "device", device, "action", m.Action)
		return fail("The script finished, but its output was not a valid result of the version the server sent.", "bad_result")
	}
	var data, errJSON []byte
	if res.OK {
		data = res.Data
	} else if errJSON, err = json.Marshal(res.Error); err != nil {
		return true, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO winmod_run_results (run_id, organization_id, site_id, device_id, module, action, version, ok, sensitive, data, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (run_id) DO NOTHING`,
		run, org, site, device, m.Module, m.Action, m.Version, res.OK, a.Sensitive, nullJSON(data), nullJSON(errJSON)); err != nil {
		return true, err
	}
	if err := keepSnapshot(ctx, tx, a, device, params, res, s.now()); err != nil {
		return true, err
	}
	if _, err := tx.Exec(ctx, `UPDATE job_runs SET `+scrubOutput+` WHERE id = $1`, run); err != nil {
		return true, err
	}
	if !res.OK {
		if _, err := tx.Exec(ctx, `UPDATE job_runs SET status = 'failed', error = $2 WHERE id = $1`, run,
			truncateRunes(res.Error.Code+": "+res.Error.Message, agentproto.MaxJobError)); err != nil {
			return true, err
		}
	}
	return true, audited(res.OK, res.Count, "")
}

// keepSnapshot stores a successful snapshot read's typed result for its
// device, action and parameters, replacing an older one; a successful action
// that changes the module's state drops the module's snapshots of the device
// instead (ADR-0073 section 5). A failed run changes nothing.
func keepSnapshot(ctx context.Context, tx pgx.Tx, a winmod.Action, device uuid.UUID, params []byte, res *winmod.Result, now time.Time) error {
	if !res.OK {
		return nil
	}
	if a.Changes {
		_, err := tx.Exec(ctx, `DELETE FROM windows_module_snapshots WHERE device_id = $1 AND module = $2`, device, string(a.Module))
		return err
	}
	if a.Freshness <= 0 {
		return nil
	}
	key, err := winmod.ParamsKey(params)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO windows_module_snapshots (device_id, module, action, params_hash, taken_at, sensitive, data)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (device_id, action, params_hash) DO UPDATE SET taken_at = excluded.taken_at, sensitive = excluded.sensitive, data = excluded.data
		WHERE windows_module_snapshots.taken_at <= excluded.taken_at`,
		device, string(a.Module), a.Name, key, now, a.Sensitive, []byte(res.Data))
	return err
}

// WinmodResult is a run's typed result for a person.
type WinmodResult struct {
	RunID      uuid.UUID  `json:"runId"`
	DeviceID   uuid.UUID  `json:"deviceId"`
	Action     string     `json:"action"`
	Version    int        `json:"version"`
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
	FinishedAt *time.Time `json:"finishedAt"`
	// OK, Data and Failure are set once the run reported a typed result.
	OK      *bool           `json:"ok,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Failure json.RawMessage `json:"failure,omitempty"`
}

// ReadWinmodResult returns a winmod run's typed result. It needs the
// action's permission on the device and, for a sensitive result, the
// action's view-sensitive permission; anything else is not found.
func (s *Service) ReadWinmodResult(ctx context.Context, c access.Caller, run uuid.UUID) (*WinmodResult, error) {
	if s.catalog == nil {
		return nil, apperr.NotFound()
	}
	var (
		out       = &WinmodResult{RunID: run}
		org, site uuid.UUID
		rec       []byte
	)
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT r.device_id, r.organization_id, r.site_id, r.status, r.error, r.finished_at, j.winmod
			FROM job_runs r JOIN jobs j ON j.id = r.job_id WHERE r.id = $1 AND j.kind = 'winmod'`, run).
			Scan(&out.DeviceID, &org, &site, &out.Status, &out.Error, &out.FinishedAt, &rec)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		var m winmodRecord
		if err := json.Unmarshal(rec, &m); err != nil {
			return err
		}
		a, ok := s.catalog.Lookup(m.Action)
		if !ok || !c.Can(a.Permission, rbac.Site(org, site)) {
			return apperr.NotFound()
		}
		out.Action, out.Version = m.Action, m.Version
		if a.Sensitive && !c.Can(a.SensitivePermission, rbac.Site(org, site)) {
			return apperr.NotFound()
		}
		var ok2 bool
		var data, failure []byte
		err = tx.QueryRow(ctx, `SELECT ok, data, error FROM winmod_run_results WHERE run_id = $1`, run).Scan(&ok2, &data, &failure)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.OK, out.Data, out.Failure = &ok2, data, failure
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
