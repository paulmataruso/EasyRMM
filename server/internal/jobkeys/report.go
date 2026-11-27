package jobkeys

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
)

// MaxReported is how many keys a report may name: the agent trusts at most
// MaxTrustedKeys, and a report of more is not believed.
const MaxReported = 2 * agentproto.MaxTrustedKeys

// Observation is what a request tells the server of the keys its device
// trusts: the heartbeat's or the job poll's report, the time of the signed
// request, and the build the device runs.
type Observation struct {
	Device uuid.UUID
	Org    uuid.UUID
	Site   uuid.UUID
	// Label is the device's hostname, the actor of the audit records.
	Label string
	IP    netip.Addr
	// Keys is the report; empty when the request carried none.
	Keys []agentproto.TrustedKey
	// Authorities are the SHA-256 fingerprints of the certificates in the
	// agent's ca.pem (heartbeats only); nil when the request carried none.
	Authorities []string
	// SignedAt is the time of the signed request: a report is stored only when
	// it is newer than the stored one, so that a poll held open while a
	// heartbeat moved the device never writes its older report over it.
	SignedAt time.Time
	// Build is the SHA-256 of the agent's executable, "" when unknown.
	Build string
}

// parseReport reads a report: every key valid, none twice, at most
// MaxReported. A report that is not is not believed at all.
func parseReport(in []agentproto.TrustedKey) ([]reported, bool) {
	if len(in) == 0 || len(in) > MaxReported {
		return nil, false
	}
	out := make([]reported, 0, len(in))
	for _, k := range in {
		pub, err := agentproto.DecodeKey(k.Key)
		if err != nil || k.Generation < 0 || slices.ContainsFunc(out, func(r reported) bool { return ed25519.PublicKey(r.Key).Equal(pub) }) {
			return nil, false
		}
		out = append(out, reported{Key: pub, Generation: k.Generation})
	}
	slices.SortFunc(out, func(a, b reported) int {
		if a.Generation != b.Generation {
			return int(a.Generation - b.Generation)
		}
		return slices.Compare(a.Key, b.Key)
	})
	return out, true
}

// Observe stores what a request says its device trusts, in the transaction of
// the request and before anything is signed for the device. The report is
// written only when it changes (or the build it came with does), and only
// when the request is newer than the stored report. A key in it that this
// server never held is recorded on the device and audited once per device and
// key ("Trusts an unknown key"); the flag clears, audited, when the device no
// longer reports the key.
func (r *Ring) Observe(ctx context.Context, tx pgx.Tx, o Observation) error {
	if len(o.Keys) > 0 {
		if err := r.observeKeys(ctx, tx, o); err != nil {
			return err
		}
	}
	if o.Authorities != nil {
		auth := slices.Clone(o.Authorities)
		if len(auth) > agentproto.MaxKeyReportAuthorities {
			auth = auth[:agentproto.MaxKeyReportAuthorities]
		}
		slices.Sort(auth)
		auth = slices.Compact(auth)
		if _, err := tx.Exec(ctx, `UPDATE devices SET agent_authorities = $2, agent_authorities_at = $3
			WHERE id = $1 AND agent_authorities IS DISTINCT FROM $2`, o.Device, auth, o.SignedAt); err != nil {
			return err
		}
	}
	return nil
}

func (r *Ring) observeKeys(ctx context.Context, tx pgx.Tx, o Observation) error {
	rep, ok := parseReport(o.Keys)
	if !ok {
		r.log.Warn("jobkeys: a device sent a key report that is not valid; it was not stored", "device_id", o.Device)
		return nil
	}
	var (
		raw      []byte
		at       *time.Time
		sha      *string
		firstAt  *time.Time
		stored   []reported
		build    = nullString(o.Build)
		signedAt = o.SignedAt
	)
	err := tx.QueryRow(ctx, `SELECT job_keys_report, job_keys_report_at, job_keys_report_sha, job_keys_first_reported_at
		FROM devices WHERE id = $1 FOR UPDATE`, o.Device).Scan(&raw, &at, &sha, &firstAt)
	if err != nil {
		return err
	}
	if at != nil && !signedAt.After(*at) {
		return nil // older than what is stored: the stored report stands
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &stored)
	}
	same := len(stored) == len(rep) && slices.EqualFunc(stored, rep, func(a, b reported) bool {
		return a.Generation == b.Generation && slices.Equal(a.Key, b.Key)
	})
	sameBuild := (sha == nil) == (build == nil) && (sha == nil || *sha == *build)
	if !same || !sameBuild || firstAt == nil {
		doc, err := json.Marshal(rep)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET job_keys_report = $2, job_keys_report_at = $3, job_keys_report_sha = $4,
				job_keys_first_reported_at = coalesce(job_keys_first_reported_at, $3)
			WHERE id = $1`, o.Device, doc, signedAt, build); err != nil {
			return err
		}
	}
	return r.flagUnknown(ctx, tx, o, rep)
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// flagUnknown keeps the device's "Trusts an unknown key" rows equal to the
// keys of its report that the ring has never held.
func (r *Ring) flagUnknown(ctx context.Context, tx pgx.Tx, o Observation, rep []reported) error {
	var unknown []reported
	for _, k := range rep {
		if _, ok := r.lookup(ctx, k.Key); !ok {
			unknown = append(unknown, k)
		}
	}
	rows, err := tx.Query(ctx, `SELECT fingerprint FROM device_unknown_keys WHERE device_id = $1`, o.Device)
	if err != nil {
		return err
	}
	var have []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			rows.Close()
			return err
		}
		have = append(have, fp)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	want := make([]string, len(unknown))
	for i, k := range unknown {
		want[i] = agentproto.Fingerprint(k.Key)
	}
	actor := audit.Actor{Type: audit.ActorAgent, ID: o.Device, Label: o.Label, SourceIP: o.IP}
	for i, k := range unknown {
		if slices.Contains(have, want[i]) {
			if _, err := tx.Exec(ctx, `UPDATE device_unknown_keys SET generation = $3, last_seen_at = now()
				WHERE device_id = $1 AND fingerprint = $2 AND generation <> $3`, o.Device, want[i], k.Generation); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_unknown_keys (device_id, fingerprint, public_key, generation) VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING`, o.Device, want[i], k.Key, k.Generation); err != nil {
			return err
		}
		if err := r.write(ctx, tx, audit.Event{Actor: actor, Action: "device.job_key_unknown", Outcome: audit.Success,
			OrganizationID: o.Org, SiteID: o.Site, DeviceID: o.Device, TargetType: "device", TargetID: o.Device.String(),
			Details: map[string]any{"fingerprint": want[i], "generation": k.Generation}}); err != nil {
			return err
		}
	}
	for _, fp := range have {
		if slices.Contains(want, fp) {
			continue
		}
		if _, err := tx.Exec(ctx, `DELETE FROM device_unknown_keys WHERE device_id = $1 AND fingerprint = $2`, o.Device, fp); err != nil {
			return err
		}
		if err := r.write(ctx, tx, audit.Event{Actor: actor, Action: "device.job_key_unknown_cleared", Outcome: audit.Success,
			OrganizationID: o.Org, SiteID: o.Site, DeviceID: o.Device, TargetType: "device", TargetID: o.Device.String(),
			Details: map[string]any{"fingerprint": fp}}); err != nil {
			return err
		}
	}
	return nil
}

func (r *Ring) write(ctx context.Context, tx pgx.Tx, e audit.Event) error {
	if r.audit == nil {
		return nil
	}
	return r.audit.Write(ctx, tx, e)
}

// RefusedStatement audits a statement an agent refused, with the agent's
// reason, once per device and statement ID: the agent reports it until an
// answer no longer carries the statement.
func (r *Ring) RefusedStatement(ctx context.Context, tx pgx.Tx, o Observation, ref agentproto.KeyRefusal) error {
	if ref.ID == "" || len(ref.ID) > 64 || (ref.Statement != agentproto.InstructionHandover && ref.Statement != agentproto.InstructionCutover) {
		return nil
	}
	reason := ref.Reason
	if len(reason) > agentproto.MaxKeyRefusal {
		reason = reason[:agentproto.MaxKeyRefusal]
	}
	var seen bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_log WHERE action = 'device.job_key_refused' AND device_id = $1
			AND details->>'id' = $2 AND details->>'statement' = $3)`, o.Device, ref.ID, ref.Statement).Scan(&seen); err != nil {
		return err
	}
	if seen {
		return nil
	}
	return r.write(ctx, tx, audit.Event{Actor: audit.Actor{Type: audit.ActorAgent, ID: o.Device, Label: o.Label, SourceIP: o.IP},
		Action: "device.job_key_refused", Outcome: audit.Success,
		OrganizationID: o.Org, SiteID: o.Site, DeviceID: o.Device, TargetType: "device", TargetID: o.Device.String(),
		Details: map[string]any{"statement": ref.Statement, "id": ref.ID, "reason": reason}})
}
