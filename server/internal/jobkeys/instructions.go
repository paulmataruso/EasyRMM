package jobkeys

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// The instruction log (ADR-0057). Every instruction an agent accepts is in a
// log it sends with its heartbeats. The server compares each entry with
// issued_instructions, the table appended to wherever the server signs
// something for a device: an entry whose kind, ID, device and key match no
// row is flagged, "Ran instructions this server never issued". The rows that
// drive the work are not what it checks against, since they do not last: an
// update's row is deleted when the device comes back on the new build.
//
// It is a tripwire, not proof: code that ran as root can erase the log before
// it is sent.

// LogDevice is the device a log comes from.
type LogDevice struct {
	ID    uuid.UUID
	Org   uuid.UUID
	Site  uuid.UUID
	Label string
}

// LogResult is what the server answers a log with.
type LogResult struct {
	// Ack is the sequence of the last entry of the device's log this server
	// took, for the answer's InstructionAck.
	Ack uint64
	// Flagged is how many entries were flagged by this report.
	Flagged int
	// Ahead is true when the device claimed more than the server recorded.
	Ahead bool
}

// maxEntryAge is how old an entry may be and still be checked: the rows that
// would match it are kept IssuedKeep.
const maxEntryAge = IssuedKeep

// AcceptLog records a device's instruction log in the transaction of its
// heartbeat: it compares the entries after the sequence the server holds,
// flags those matching nothing issued, and answers with the sequence taken.
//
// An entry older than 90 days, or dated before the server's last restore (the
// host's `incident restored`), is *not checked*: the rows that would match it
// may be gone. A restore nobody recorded shows when the device says the
// server acknowledged more of its log than the database recorded. That is the
// device's own claim, and a device key someone holds could make it, so it
// counts for that device alone: its entries dated before this heartbeat become
// not checked, its flags raised for such entries are withdrawn, audited with
// both sequences, and a possible unrecorded restore is recorded for the
// super administrators, which `incident restored` confirms and applies to
// every device.
func (r *Ring) AcceptLog(ctx context.Context, tx pgx.Tx, d LogDevice, rep agentproto.InstructionLogReport, now time.Time) (LogResult, error) {
	var (
		recorded   uint64
		notChecked *time.Time
	)
	err := tx.QueryRow(ctx, `INSERT INTO device_instruction_log (device_id) VALUES ($1)
		ON CONFLICT (device_id) DO UPDATE SET updated_at = device_instruction_log.updated_at
		RETURNING acked_seq, not_checked_before`, d.ID).Scan(&recorded, &notChecked)
	if err != nil {
		return LogResult{}, err
	}
	res := LogResult{Ack: recorded}
	actor := audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: d.Label}
	if rep.Acked > recorded {
		// The device claims the server took more than it recorded.
		res.Ahead = true
		var withdrawn int64
		tag, err := tx.Exec(ctx, `UPDATE device_instruction_flags SET withdrawn_at = now()
			WHERE device_id = $1 AND withdrawn_at IS NULL AND entry_at < $2`, d.ID, now)
		if err != nil {
			return LogResult{}, err
		}
		withdrawn = tag.RowsAffected()
		if _, err := tx.Exec(ctx, `UPDATE device_instruction_log SET acked_seq = $2, not_checked_before = $3, ahead_at = $3,
				ahead_claimed = $2, ahead_recorded = $4, updated_at = now() WHERE device_id = $1`,
			d.ID, int64(rep.Acked), now, int64(recorded)); err != nil { //nolint:gosec // bounded by the agent's log size
			return LogResult{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO server_restores (restored_at, source, devices) VALUES ($1, 'suspected', ARRAY[$2]::uuid[])`, now, d.ID); err != nil {
			return LogResult{}, err
		}
		if err := r.write(ctx, tx, audit.Event{Actor: actor, Action: "device.instruction_log_ahead", Outcome: audit.Success,
			OrganizationID: d.Org, SiteID: d.Site, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"claimed": rep.Acked, "recorded": recorded, "flagsWithdrawn": withdrawn, "alert": "possible unrecorded restore"}}); err != nil {
			return LogResult{}, err
		}
		recorded, notChecked = rep.Acked, &now
		res.Ack = rep.Acked
	}
	// The server's last recorded restore, which applies to every device.
	var restored *time.Time
	if err := tx.QueryRow(ctx, `SELECT max(restored_at) FROM server_restores WHERE source = 'incident'`).Scan(&restored); err != nil {
		return LogResult{}, err
	}
	entries := rep.Entries
	if len(entries) > agentproto.MaxInstructionBatch {
		entries = entries[:agentproto.MaxInstructionBatch]
	}
	slices.SortFunc(entries, func(a, b agentproto.LoggedInstruction) int {
		switch {
		case a.Seq < b.Seq:
			return -1
		case a.Seq > b.Seq:
			return 1
		}
		return 0
	})
	var flagged []map[string]any
	top := recorded
	for _, e := range entries {
		if !e.Valid() || e.Seq <= recorded {
			continue
		}
		top = max(top, e.Seq)
		if (notChecked != nil && e.At.Before(*notChecked)) || (restored != nil && e.At.Before(*restored)) || now.Sub(e.At) > maxEntryAge {
			continue // not checked
		}
		key, known := r.ByFingerprint(e.Signer)
		var matched bool
		if known {
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM issued_instructions
				WHERE device_id = $1 AND kind = $2 AND instruction_id = $3 AND generation = $4)`,
				d.ID, e.Kind, e.ID, key.Generation).Scan(&matched); err != nil {
				return LogResult{}, err
			}
		}
		if matched {
			continue
		}
		tag, err := tx.Exec(ctx, `INSERT INTO device_instruction_flags (device_id, seq, kind, instruction_id, signer, entry_at)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (device_id, seq) DO NOTHING`, d.ID, int64(e.Seq), e.Kind, e.ID, e.Signer, e.At) //nolint:gosec // bounded
		if err != nil {
			return LogResult{}, err
		}
		if tag.RowsAffected() > 0 {
			flagged = append(flagged, map[string]any{"kind": e.Kind, "id": e.ID, "signer": e.Signer, "at": e.At.UTC().Format(time.RFC3339)})
		}
	}
	if top > recorded {
		if _, err := tx.Exec(ctx, `UPDATE device_instruction_log SET acked_seq = $2, updated_at = now() WHERE device_id = $1`, d.ID, int64(top)); err != nil { //nolint:gosec // bounded
			return LogResult{}, err
		}
		res.Ack = top
	}
	if len(flagged) > 0 {
		res.Flagged = len(flagged)
		if err := r.write(ctx, tx, audit.Event{Actor: actor, Action: "device.instruction_unknown", Outcome: audit.Success,
			OrganizationID: d.Org, SiteID: d.Site, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
			Details: map[string]any{"entries": flagged}}); err != nil {
			return LogResult{}, err
		}
	}
	return res, nil
}

// RecordRestore records that the server was restored from a backup, as the
// host's `incident restored` does: every device's entries dated before it
// become not checked, and a possible unrecorded restore that was raised is
// confirmed. at is when the restore happened (now, unless the operator gives
// a time).
func RecordRestore(ctx context.Context, db *database.DB, auditLog *audit.Logger, at time.Time) (confirmed int64, err error) {
	err = db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO server_restores (restored_at, source) VALUES ($1, 'incident')`, at); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE server_restores SET confirmed_at = now() WHERE source = 'suspected' AND confirmed_at IS NULL`)
		if err != nil {
			return err
		}
		confirmed = tag.RowsAffected()
		// Flags raised for entries the restore made not checked are withdrawn.
		if _, err := tx.Exec(ctx, `UPDATE device_instruction_flags SET withdrawn_at = now() WHERE withdrawn_at IS NULL AND entry_at < $1`, at); err != nil {
			return err
		}
		return auditLog.Write(ctx, tx, audit.Event{Actor: audit.SystemActor("incident"), Action: "server.restored", Outcome: audit.Success,
			TargetType: "server", Details: map[string]any{"how": "easyrmm-server incident restored", "notCheckedBefore": at.UTC().Format(time.RFC3339),
				"alertsConfirmed": confirmed}})
	})
	return confirmed, err
}
