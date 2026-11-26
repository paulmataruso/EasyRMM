package easypatch

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// heldMessage is why an install waits: a Windows hardening change on the
// computer has not yet been confirmed (ADR-0054, One change at a time). The
// confirmation comes within minutes, or the computer undoes the change
// itself; either way the install may then go.
const heldMessage = "Not sent: a hardening change on this computer is waiting for its confirmation (ADR-0054). Try again in a few minutes."

// hardeningHeld reports whether the device has a hardening change whose
// guard is armed: one change at a time on a computer, EasyPatch's installs
// among them.
func (s *Service) hardeningHeld(ctx context.Context, device uuid.UUID) (bool, error) {
	var held bool
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM hardening_guards WHERE device_id = $1 AND state = 'armed' AND rollback_at > now() - interval '3 minutes')`,
			device).Scan(&held)
	})
	return held, err
}
