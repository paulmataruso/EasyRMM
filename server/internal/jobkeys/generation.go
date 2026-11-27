package jobkeys

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// NextGeneration is the generation of a key made now (ADR-0057): the largest
// of the time in milliseconds, the ring's highest generation plus one, and the
// highest generation any device or removed device has reported, among those
// at most agentproto.MaxSkew ahead of the server's clock, plus one.
//
// Generations only increase, even across a restore. The ring's term covers
// keys this ring made; the reported term covers keys made before a restore
// that the restored ring never held, and keys someone handed a device. The
// bound is the one agents apply to a hand-over, so no report pushes
// generations far ahead: a report an hour ahead is flagged as an unknown key
// and lies outside it. It runs inside the transaction that makes the key,
// under the ring's lock.
func (r *Ring) NextGeneration(ctx context.Context, tx pgx.Tx, now time.Time) (int64, error) {
	next := now.UnixMilli()
	if highest := r.Newest().Generation + 1; highest > next {
		next = highest
	}
	bound := now.Add(agentproto.MaxSkew).UnixMilli()
	var reported *int64
	// The generations are in the reports' JSON documents of devices and of
	// removed devices.
	err := tx.QueryRow(ctx, `SELECT max((k->>'generation')::bigint) FROM (
			SELECT jsonb_array_elements(job_keys_report) AS k FROM devices WHERE job_keys_report IS NOT NULL
			UNION ALL
			SELECT jsonb_array_elements(job_keys_report) FROM retired_devices WHERE job_keys_report IS NOT NULL
		) reports WHERE (k->>'generation')::bigint <= $1`, bound).Scan(&reported)
	if err != nil {
		return 0, err
	}
	if reported != nil && *reported+1 > next {
		next = *reported + 1
	}
	return next, nil
}
