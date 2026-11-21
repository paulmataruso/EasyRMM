package host

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The rollback's work in the database (ADR-0052): the discarded version's
// audit chain head is recorded, the audit IDs move past every ID it wrote,
// and a record of the rollback is appended through the database's own
// audit function, which keeps the chain.

// unknownHeadMargin is how far audit IDs skip when the discarded database
// cannot be read: past any number of records an upgrade's few minutes
// could write.
const unknownHeadMargin = 1_000_000

// auditHead is a database's last audit record.
type auditHead struct {
	// LastID is the highest ID handed out, by the sequence or a record.
	LastID int64
	// Head is the last record's hash, in hexadecimal; "" when there is
	// no record.
	Head string
}

var headRE = regexp.MustCompile(`^([0-9]+)\|([0-9a-f]{64})?$`)

// readAuditHead reads the audit chain's head from the PostgreSQL of the
// deployment in dir, which must be running.
func (d Docker) readAuditHead(ctx context.Context, dir string) (*auditHead, error) {
	out, err := d.Psql(ctx, dir, `SELECT greatest(
    coalesce((SELECT max(id) FROM public.audit_log), 0),
    coalesce(pg_sequence_last_value(pg_get_serial_sequence('public.audit_log', 'id')::regclass), 0))
  || '|' || coalesce((SELECT encode(entry_hash, 'hex') FROM public.audit_log ORDER BY id DESC LIMIT 1), '');
`, nil)
	if err != nil {
		return nil, err
	}
	m := headRE.FindStringSubmatch(out)
	if m == nil {
		return nil, fmt.Errorf("the audit chain's head: unexpected %q", out)
	}
	id, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return nil, err
	}
	return &auditHead{LastID: id, Head: m[2]}, nil
}

// rollbackRecord is the details of the audit record a rollback appends.
type rollbackRecord struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
	// DiscardedHead is the discarded database's chain head, or "unknown".
	DiscardedHead string `json:"discardedHead"`
	// DiscardedLastID is the highest audit ID it handed out, when known.
	DiscardedLastID *int64    `json:"discardedLastId"`
	BackupTaken     time.Time `json:"backupTaken"`
}

// recordRollback moves the restored database's audit IDs past every ID
// the discarded one wrote (by a fixed margin when it could not be read)
// and appends the rollback's record. The deployment's PostgreSQL must be
// running and nothing else.
func (d Docker) recordRollback(ctx context.Context, dir string, discarded *auditHead, r rollbackRecord) error {
	skipTo, margin := int64(0), int64(unknownHeadMargin)
	r.DiscardedHead = "unknown"
	if discarded != nil {
		skipTo, margin = discarded.LastID, 0
		r.DiscardedHead, r.DiscardedLastID = discarded.Head, &discarded.LastID
		if discarded.Head == "" {
			r.DiscardedHead = "none"
		}
	}
	details, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = d.Psql(ctx, dir, `SELECT setval(pg_get_serial_sequence('public.audit_log', 'id'), greatest(1, :'skip_to'::bigint,
    greatest(coalesce((SELECT max(id) FROM public.audit_log), 0),
             coalesce(pg_sequence_last_value(pg_get_serial_sequence('public.audit_log', 'id')::regclass), 0)) + :'margin'::bigint));
SELECT public.easyrmm_audit_append(now(), 'system', NULL, 'easyrmm-updater', NULL, NULL, NULL,
    'updater.rolled_back', 'version', :'discarded', 'success', NULL, '', :'details'::jsonb);
`, map[string]string{
		"skip_to":   strconv.FormatInt(skipTo, 10),
		"margin":    strconv.FormatInt(margin, 10),
		"discarded": r.From,
		"details":   string(details),
	})
	return err
}

// Loss is what a rollback after a confirmed upgrade loses: everything
// written since its backup.
type Loss struct {
	Since time.Time `json:"since"`
	// Devices names (up to 50) the devices enrolled since, which must
	// enroll again; DeviceCount counts them all.
	Devices     []string `json:"devices"`
	DeviceCount int      `json:"deviceCount"`
	Jobs        int      `json:"jobs"`
	Audit       int      `json:"audit"`
}

func (l Loss) String() string {
	s := fmt.Sprintf("everything written since %s: %d devices enrolled since (they must enroll again), %d jobs, %d audit records",
		l.Since.UTC().Format("2006-01-02 15:04 UTC"), l.DeviceCount, l.Jobs, l.Audit)
	if len(l.Devices) > 0 {
		s += "\n  devices to enroll again: " + strings.Join(l.Devices, ", ")
		if l.DeviceCount > len(l.Devices) {
			s += fmt.Sprintf(" and %d more", l.DeviceCount-len(l.Devices))
		}
	}
	return s
}

// lossSince counts what the running deployment's database holds that was
// written since t.
func (d Docker) lossSince(ctx context.Context, dir string, t time.Time) (*Loss, error) {
	out, err := d.Psql(ctx, dir, `SELECT json_build_object(
    'devices', (SELECT coalesce(json_agg(name ORDER BY created_at), '[]'::json)
                FROM (SELECT name, created_at FROM public.devices WHERE created_at >= :'since'::timestamptz
                      ORDER BY created_at LIMIT 50) d),
    'deviceCount', (SELECT count(*) FROM public.devices WHERE created_at >= :'since'::timestamptz),
    'jobs', (SELECT count(*) FROM public.jobs WHERE created_at >= :'since'::timestamptz),
    'audit', (SELECT count(*) FROM public.audit_log WHERE occurred_at >= :'since'::timestamptz));
`, map[string]string{"since": t.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		return nil, err
	}
	l := &Loss{Since: t}
	if err := json.Unmarshal([]byte(out), l); err != nil {
		return nil, fmt.Errorf("what a rollback loses: unexpected %q", out)
	}
	l.Since = t
	return l, nil
}
