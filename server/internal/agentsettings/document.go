package agentsettings

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// Delivery of settings to agents (ADR-0058, slice 2). A heartbeat that carries
// the agent's report (what it understands, the version it holds, the interval
// it uses) goes through Follow: the server records the report, and issues the
// device's effective settings as a signed document when they changed.

// NotAppliedAfter is how many heartbeats with the report, since the current
// version was issued, the agent may send without reporting it applied before
// the device is flagged *Not applied*.
const NotAppliedAfter = 3

// Beat is what a heartbeat tells Follow.
type Beat struct {
	Device DeviceRef
	// Build names the build that sent it: the SHA-256 of its executable, or
	// "version:<v>" for an agent that sends none. A report holds only while
	// the heartbeats come from that build.
	Build string
	// Capabilities, Report and HeartbeatSeconds are the agent's report; nil
	// Capabilities is a heartbeat without it (the first of a process), which
	// changes nothing but the time of the latest heartbeat.
	Capabilities     *agentproto.SettingsCapabilities
	Report           *agentproto.SettingsReport
	HeartbeatSeconds int
	// SignedAt is the time in the heartbeat's signature, on the agent's
	// clock: a heartbeat signed before the latest processed is not
	// processed.
	SignedAt time.Time
	// Now is the server's clock.
	Now time.Time
}

// DeviceRef names the device whose heartbeat it is.
type DeviceRef struct{ ID, Org, Site uuid.UUID }

// Signer returns the private key to sign a document for a device with, and
// records that the server signed it (jobkeys.Source.Issue).
type Signer func(ctx context.Context, tx pgx.Tx, device uuid.UUID, id string) (ed25519.PrivateKey, error)

// State is what the server keeps of a device's settings delivery.
type State struct {
	// Capabilities is what its agent last reported, nil when it reports
	// nothing (an older build, or a change of build without a report).
	Capabilities *agentproto.SettingsCapabilities
	Build        string
	// DocVersion is the last version issued (0 for none), its hash, when it
	// was issued and under which catalog.
	DocVersion        int64
	DocHash           string
	DocIssuedAt       time.Time
	DocCatalogVersion int
	// AppliedVersion is the version the agent last reported applying, its
	// hash, when it first did, and the problems it reported.
	AppliedVersion int64
	AppliedHash    string
	AppliedAt      time.Time
	Problems       map[string]string
	// NotAppliedHeartbeats counts the heartbeats with the report since
	// DocVersion was issued, counted by an instance whose catalog is not
	// older than the document's, without the version applied.
	NotAppliedHeartbeats int
	SignedAt             time.Time
}

// NotApplied says whether the device is flagged: its agent sent three
// heartbeats with the report since the current version was issued without
// reporting it applied.
func (s State) NotApplied() bool { return s.NotAppliedHeartbeats >= NotAppliedAfter }

// ReadState reads a device's state; the zero State when it has none.
func ReadState(ctx context.Context, tx pgx.Tx, device uuid.UUID) (State, error) {
	st, found, err := readState(ctx, tx, device, false)
	if err != nil || !found {
		return State{}, err
	}
	return st, nil
}

func readState(ctx context.Context, tx pgx.Tx, device uuid.UUID, lock bool) (State, bool, error) {
	q := `SELECT capabilities, coalesce(capabilities_build, ''), coalesce(doc_version, 0), coalesce(doc_hash, ''),
			doc_issued_at, coalesce(doc_catalog_version, 0), applied_version, coalesce(applied_hash, ''), applied_at,
			problems, not_applied_heartbeats, heartbeat_signed_at
		FROM agent_device_state WHERE device_id = $1`
	if lock {
		q += ` FOR UPDATE`
	}
	var (
		st                         State
		docAt, appliedAt, signedAt *time.Time
	)
	err := tx.QueryRow(ctx, q, device).Scan(&st.Capabilities, &st.Build, &st.DocVersion, &st.DocHash, &docAt, &st.DocCatalogVersion,
		&st.AppliedVersion, &st.AppliedHash, &appliedAt, &st.Problems, &st.NotAppliedHeartbeats, &signedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	st.DocIssuedAt, st.AppliedAt, st.SignedAt = derefTime(docAt), derefTime(appliedAt), derefTime(signedAt)
	return st, true, nil
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// Follow records a heartbeat's report and returns the signed document the
// answer carries, nil for none. It runs in the heartbeat's transaction and
// reads the device's state row FOR UPDATE, so that two heartbeats at once
// (a wake's and the regular one) cannot issue one version with two contents.
// Organizations outside the development scope get nothing.
func Follow(ctx context.Context, tx pgx.Tx, log *slog.Logger, sign Signer, b Beat) (*agentproto.SignedSettings, error) {
	if !devscope.Allowed(b.Device.Org) {
		return nil, nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_device_state (device_id) VALUES ($1) ON CONFLICT DO NOTHING`, b.Device.ID); err != nil {
		return nil, err
	}
	st, _, err := readState(ctx, tx, b.Device.ID, true)
	if err != nil {
		return nil, err
	}
	if !st.SignedAt.IsZero() && b.SignedAt.Before(st.SignedAt) {
		return nil, nil // signed before one already processed: nothing moves
	}
	caps := b.Capabilities
	if caps != nil && caps.Check() != nil {
		log.Warn("agentsettings: a heartbeat's capabilities report is not valid; ignored", "device_id", b.Device.ID)
		caps = nil
	}
	if caps == nil {
		// Without the report nothing changes: the last report holds while the
		// build is the one that sent it; after a change of build without a
		// report the device counts as one whose agent reports nothing.
		if st.Capabilities != nil && st.Build != b.Build {
			_, err = tx.Exec(ctx, `UPDATE agent_device_state SET capabilities = NULL, capabilities_build = NULL, capabilities_at = NULL,
				heartbeat_signed_at = $2, updated_at = now() WHERE device_id = $1`, b.Device.ID, b.SignedAt)
		} else {
			_, err = tx.Exec(ctx, `UPDATE agent_device_state SET heartbeat_signed_at = $2 WHERE device_id = $1`, b.Device.ID, b.SignedAt)
		}
		return nil, err
	}

	// What the agent holds. A version above 2^53 - 1 cannot come from an
	// agent that follows the ADR: it is not used, and shows as a problem.
	problems := map[string]string{}
	applied := int64(0)
	if b.Report != nil && b.Report.Check() == nil {
		for k, v := range b.Report.Problems {
			problems[k] = v
		}
		applied = b.Report.Version
		if applied < 0 || applied > agentproto.MaxSettingsVersion {
			applied = 0
			problems[agentproto.SettingsDocumentKey] = "the reported version is outside 1 to 2^53 - 1"
		}
	}
	logProblems(log, b.Device.ID, st.Problems, problems)

	// Counting, before this heartbeat issues anything: a heartbeat that
	// carries the report and not the current version applied, counted only
	// by an instance whose catalog is not older than the document's.
	notApplied := st.NotAppliedHeartbeats
	appliedAt := st.AppliedAt
	if st.DocVersion > 0 {
		switch {
		case applied >= st.DocVersion:
			notApplied = 0
		case CatalogVersion >= st.DocCatalogVersion:
			notApplied++
		}
	}
	if applied != st.AppliedVersion || appliedAt.IsZero() {
		appliedAt = b.Now
	}
	appliedHash := ""
	if applied > 0 && applied == st.DocVersion {
		appliedHash = st.DocHash
	}

	doc, issued, err := issue(ctx, tx, log, sign, b, st, caps, applied)
	if err != nil {
		return nil, err
	}
	docVersion, docHash, docAt, docCat := st.DocVersion, st.DocHash, st.DocIssuedAt, st.DocCatalogVersion
	if issued != nil {
		docVersion, docHash, docAt, docCat = issued.version, issued.hash, b.Now, CatalogVersion
		notApplied = 0
		if applied == docVersion {
			appliedHash = docHash
		}
	}
	pj, _ := json.Marshal(problems) // a map of strings always encodes
	cj, _ := json.Marshal(caps)
	_, err = tx.Exec(ctx, `UPDATE agent_device_state SET
			capabilities = $2, capabilities_build = $3, capabilities_at = $4,
			doc_version = NULLIF($5::bigint, 0), doc_hash = NULLIF($6::text, ''), doc_issued_at = $7, doc_catalog_version = NULLIF($8::int, 0),
			applied_version = $9::bigint, applied_hash = NULLIF($10::text, ''), applied_at = CASE WHEN $9::bigint > 0 THEN $11::timestamptz END, problems = $12,
			not_applied_heartbeats = $13, heartbeat_signed_at = $14, updated_at = now()
		WHERE device_id = $1`,
		b.Device.ID, cj, b.Build, b.SignedAt,
		docVersion, docHash, nilTime(docAt), docCat,
		applied, appliedHash, appliedAt, pj,
		notApplied, b.SignedAt)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

func nilTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

type issuedDoc struct {
	version int64
	hash    string
}

// issue decides the document the answer carries: a new version when the
// effective settings (for the keys the agent reported) changed or the agent
// reports a version above the last issued (a restore), the current one again
// while the agent holds an older version, nothing otherwise. The second
// result is set when a new version was issued.
func issue(ctx context.Context, tx pgx.Tx, log *slog.Logger, sign Signer, b Beat, st State, caps *agentproto.SettingsCapabilities, applied int64) (*agentproto.SignedSettings, *issuedDoc, error) {
	if !caps.Takes(agentproto.CapSettings) {
		return nil, nil, nil
	}
	if st.DocVersion > 0 && st.DocCatalogVersion > CatalogVersion {
		// A newer catalog's document stands: this instance is older than the
		// one that issued it (a rolling upgrade).
		return nil, nil, nil
	}
	settings, err := effectiveFor(ctx, tx, log, b.Device, caps)
	if err != nil {
		return nil, nil, err
	}
	hash := agentproto.SettingsHash(settings)
	version, issuedAt := st.DocVersion, st.DocIssuedAt
	var fresh *issuedDoc
	if st.DocVersion == 0 || hash != st.DocHash || applied > st.DocVersion {
		version = max(b.Now.UnixMilli(), st.DocVersion+1, applied+1)
		if version > agentproto.MaxSettingsVersion {
			return nil, nil, fmt.Errorf("agentsettings: no settings version is left to issue for device %s", b.Device.ID)
		}
		issuedAt = b.Now
		fresh = &issuedDoc{version: version, hash: hash}
	} else if applied >= st.DocVersion {
		return nil, nil, nil // the agent holds the current version
	}
	key, err := sign(ctx, tx, b.Device.ID, strconv.FormatInt(version, 10))
	if err != nil {
		return nil, nil, err
	}
	signed, err := agentproto.SignSettings(key, agentproto.SettingsPayload{
		V: agentproto.SettingsPayloadVersion, DeviceID: b.Device.ID.String(), Version: version, IssuedAt: issuedAt.UTC().Truncate(time.Millisecond), Settings: settings,
	})
	if err != nil {
		return nil, nil, err
	}
	return &signed, fresh, nil
}

// effectiveFor is the device's effective settings for the keys its agent
// reported: only keys both sides know, with values valid under the highest
// schema version the server knows at or below the one the agent reported. A
// key the agent does not know, or whose value its schema does not allow, is
// left out, so the agent uses its built-in default.
func effectiveFor(ctx context.Context, tx pgx.Tx, log *slog.Logger, d DeviceRef, caps *agentproto.SettingsCapabilities) (map[string]json.RawMessage, error) {
	l, err := readLimits(ctx, tx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(caps.Settings))
	for name := range caps.Settings {
		names = append(names, name)
	}
	sort.Strings(names)
	out := map[string]json.RawMessage{}
	for _, name := range names {
		k, ok := Lookup(name)
		if !ok {
			continue
		}
		schema, ok := k.SchemaAtOrBelow(caps.Settings[name])
		if !ok {
			log.Warn("agentsettings: an agent reported a schema version of a key that the server knows none at or below; the key is left out",
				"device_id", d.ID, "key", name, "version", caps.Settings[name])
			continue
		}
		rows, err := chainRows(ctx, tx, name, Target{Scope: ScopeDevice, OrgID: d.Org, SiteID: d.Site, DeviceID: d.ID})
		if err != nil {
			return nil, err
		}
		eff := k.Resolve(rows, l)
		if schema.Check(eff.Value) != nil {
			continue
		}
		out[name] = eff.Value
	}
	return out, nil
}

// logProblems logs what the agent reported when it differs from what the
// server held: a refusal at error level (a bug, or an answer changed on the
// way), an invalid or clamped key as a warning.
func logProblems(log *slog.Logger, device uuid.UUID, held, now map[string]string) {
	keys := make([]string, 0, len(now))
	for k := range now {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if held[k] == now[k] {
			continue
		}
		if k == agentproto.SettingsDocumentKey || strings.HasPrefix(now[k], agentproto.ProblemRefused) {
			log.Error("agentsettings: an agent refused its settings document", "device_id", device, "key", k, "reason", now[k])
		} else {
			log.Warn("agentsettings: an agent did not apply a setting as sent", "device_id", device, "key", k, "problem", now[k])
		}
	}
}
