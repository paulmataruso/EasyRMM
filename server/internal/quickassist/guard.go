package quickassist

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// ErrNotHeld is what a remote tool answers for a Quick Assist device the
// caller does not hold (ADR-0080: the holder rule).
var ErrNotHeld = apperr.Conflict("quick_assist_not_held",
	"This is a Quick Assist computer. Accept its request first, and only the technician who holds the session (or someone who may take it over) can use it.")

// GuardTx is the holder rule for remote desktop, terminal, files and
// scripts: a Quick Assist device can be used only while its session is
// active and the caller holds it, or may take sessions over. Other devices
// pass untouched. It never replaces the usual permissions.
func GuardTx(ctx context.Context, tx pgx.Tx, c access.Caller, ids ...uuid.UUID) error {
	rows, err := tx.Query(ctx, `SELECT s.organization_id, s.state, s.accepted_by FROM devices d
		LEFT JOIN quick_assist_sessions s ON s.device_id = d.id
		WHERE d.id = ANY($1) AND d.quick_assist`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var org *uuid.UUID
		var state *string
		var by *uuid.UUID
		if err := rows.Scan(&org, &state, &by); err != nil {
			return err
		}
		if state == nil || *state != SessionActive || org == nil {
			return ErrNotHeld
		}
		x := &Session{Organization: *org, AcceptedBy: by}
		if !holder(c, x) {
			return ErrNotHeld
		}
	}
	return rows.Err()
}

// Guard is GuardTx in a read transaction of its own.
func Guard(ctx context.Context, db *database.DB, c access.Caller, id uuid.UUID) error {
	return db.ReadTx(ctx, database.System, func(tx pgx.Tx) error { return GuardTx(ctx, tx, c, id) })
}
