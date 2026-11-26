package jobs

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// recordSettingResults keeps what an apply or undo of single settings
// reported for each setting (ADR-0078, slice C2): the fix queue reads the
// before and after values and the outcome from it, because the job's output
// is not readable by the server's role. It runs when the run reports,
// beside the module records.
func (s *Service) recordSettingResults(ctx context.Context, tx pgx.Tx, device, job uuid.UUID, r *hardeningResult) error {
	for _, m := range r.Modules {
		for _, st := range m.Settings {
			if _, err := tx.Exec(ctx, `INSERT INTO hardening_setting_results (job_id, device_id, organization_id, setting_id, module,
					module_outcome, module_reason, outcome, state, before_value, value, note, changed_at)
				SELECT $1, d.id, d.organization_id, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12 FROM devices d WHERE d.id = $2
				ON CONFLICT (job_id, device_id, setting_id) DO NOTHING`,
				job, device, st.ID, m.Module, m.Outcome, truncateRunes(m.OutcomeReason, 600), st.Outcome, st.State,
				truncateRunes(st.Before, 600), truncateRunes(st.Value, 600), truncateRunes(st.Note, 600), truncateRunes(st.ChangedAt, 64)); err != nil {
				return err
			}
		}
	}
	return nil
}

// WindowsSettingTier is the risk tier (0 to 3) the server holds a Windows
// setting to, which the fix queue's tier table must agree with.
func WindowsSettingTier(id string) (int, bool) {
	for _, s := range windowsSettings {
		if s.ID == id {
			return windowsSettingTier(s), true
		}
	}
	return 0, false
}
