// Package gpowire joins the Group Policy module to the jobs package: the runner that starts a change as a winmod job, the hook
// that keeps a change's backup, and the gate that checks approvals. It is a package of its own because the Group Policy
// package must not import jobs (the jobs package's tests import every role, so that would be an import cycle).
package gpowire

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/grouppolicy"
)

type runner struct{ j *jobs.Service }

func (r runner) RunWinmod(ctx context.Context, c access.Caller, device uuid.UUID, action string, params json.RawMessage, confirm string) (*grouppolicy.Run, error) {
	run, err := r.j.RunWinmod(ctx, c, jobs.WinmodInput{DeviceID: device, Action: action, Params: params, Confirm: confirm})
	if err != nil {
		return nil, err
	}
	return &grouppolicy.Run{JobID: run.JobID, RunID: run.RunID, Action: run.Action, Status: run.Status, ExpiresAt: run.ExpiresAt}, nil
}

// New builds the Group Policy service on the jobs service and registers its hook and its approval gate with it.
func New(db *database.DB, a *audit.Logger, mods *modules.Service, catalog *winmod.Catalog, j *jobs.Service) *grouppolicy.Service {
	s := grouppolicy.New(db, a, mods, catalog, runner{j})
	j.OnWinmodResult(func(ctx context.Context, tx pgx.Tx, ev jobs.WinmodResultEvent) error {
		return s.Hook(ctx, tx, grouppolicy.ResultEvent{Action: ev.Action, RunID: ev.RunID, JobID: ev.JobID, DeviceID: ev.DeviceID, OrgID: ev.OrgID, SiteID: ev.SiteID,
			Stdout: ev.Stdout, Result: ev.Result, Params: ev.Params})
	})
	j.SetApprovals(s)
	return s
}
