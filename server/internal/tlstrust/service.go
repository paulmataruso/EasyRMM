// Package tlstrust is the server's side of ADR-0055's agent trust (slice 5b1):
// it asks a device's agent, with a signed instruction in the heartbeat answer,
// to verify the certificate chains a name is served with and, for a move, to
// widen its trust, and it keeps what each device answered (device_tls_trust).
// It changes no name and no certificate: it learns what devices trust.
package tlstrust

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// Chain is a certificate chain a name is, or will be, served with: DER, leaf
// first, and why it is asked about.
type Chain struct {
	Purpose string // agentproto.TrustServed, TrustFallback or TrustTarget
	DER     [][]byte
}

// Source says what a host is served with. The edge implements it; 5b2's moves
// add the fallback and the target.
type Source interface {
	// Chains returns the chains to verify for a host: the one served now, and
	// the fallback's when the name has one that differs. Empty for a host
	// this server serves no certificate for.
	Chains(host string) []Chain
}

// Device is what the service needs of a device.
type Device struct {
	ID       uuid.UUID
	Org      uuid.UUID
	Site     uuid.UUID
	Hostname string
	Platform string
}

// Beat is what a heartbeat tells the service.
type Beat struct {
	// Origin is the host name the request arrived at, as the agent's
	// configured server names it.
	Origin string
	IP     netip.Addr
	// Caps are the heartbeat's capabilities; the instruction is sent only
	// when it lists agentproto.CapTrust.
	Caps []string
	// AgentSHA256 is the build's hash, to tell a new build from the last.
	AgentSHA256 string
	Report      *agentproto.TrustReport
}

// Service keeps the verifications and builds instructions.
type Service struct {
	db    *database.DB
	audit *audit.Logger
	key   ed25519.PrivateKey
	log   *slog.Logger
	now   func() time.Time

	mu  sync.RWMutex
	src Source
	// easyPatchHost, when set, names the host a device's EasyPatch agent uses
	// (empty when it has none).
	easyPatchHost func(ctx context.Context, device uuid.UUID) string
}

// New builds the service. key is the job key that signs instructions.
func New(db *database.DB, auditLog *audit.Logger, key ed25519.PrivateKey, log *slog.Logger) *Service {
	return &Service{db: db, audit: auditLog, key: key, log: log, now: time.Now}
}

// SetSource tells the service what hosts are served with. Until it is set the
// service asks about nothing by itself.
func (s *Service) SetSource(src Source) {
	s.mu.Lock()
	s.src = src
	s.mu.Unlock()
}

// SetEasyPatchHost tells the service how to find the host of a device's
// EasyPatch agent, to have its chains verified against the system's roots.
func (s *Service) SetEasyPatchHost(f func(ctx context.Context, device uuid.UUID) string) {
	s.mu.Lock()
	s.easyPatchHost = f
	s.mu.Unlock()
}

func (s *Service) source() Source {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.src
}

// row is a verification asked of one device.
type row struct {
	scope, host, purpose string
	chain                [][]byte
	addCerts             [][]byte
}

func (r row) digest() string { return agentproto.TrustChainDigest(r.chain) }

// chainID names a row inside an instruction.
func (r row) chainID() string {
	return r.scope + "-" + r.purpose + "-" + r.digest()[:12]
}

// Target is a move's question to a device: verify these chains for the origin
// (and the EasyPatch host) and, when every target chain verifies, add these
// certificates to the agent's trust and widen it. 5b2 builds moves on it.
type Target struct {
	Origin string
	Chains []Chain
	// AddCerts are DER certificates of authorities.
	AddCerts [][]byte
	// EasyPatchHost and EasyPatchChains are verified against the system's
	// roots alone.
	EasyPatchHost   string
	EasyPatchChains []Chain
}

func (t Target) rows() []row {
	var out []row
	for _, c := range t.Chains {
		out = append(out, row{scope: agentproto.TrustScopeAgent, host: t.Origin, purpose: c.Purpose, chain: c.DER, addCerts: t.AddCerts})
	}
	for _, c := range t.EasyPatchChains {
		out = append(out, row{scope: agentproto.TrustScopeEasyPatch, host: t.EasyPatchHost, purpose: c.Purpose, chain: c.DER})
	}
	return out
}

// Ask has each device verify what a target names: its rows are written as
// pending, whatever they held, and sent with the device's next heartbeat that
// reports the capability. A device that answered the same question already
// keeps its answer unless force is set.
func (s *Service) Ask(ctx context.Context, devices []uuid.UUID, t Target, force bool) error {
	rows := t.rows()
	if err := validate(rows); err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, d := range devices {
			if _, err := s.upsert(ctx, tx, d, rows, force); err != nil {
				return err
			}
		}
		return nil
	})
}

func validate(rows []row) error {
	if len(rows) == 0 {
		return errors.New("tlstrust: nothing to verify")
	}
	for _, r := range rows {
		switch r.purpose {
		case agentproto.TrustServed, agentproto.TrustFallback, agentproto.TrustTarget:
		default:
			return fmt.Errorf("tlstrust: purpose %q", r.purpose)
		}
		if r.host == "" || len(r.chain) == 0 || len(r.chain) > agentproto.MaxTrustChainLen {
			return errors.New("tlstrust: a chain with no host, or no certificates, or too many")
		}
	}
	return nil
}

// upsert writes the rows pending where they are new or changed (or force).
// It reports whether any row is now pending.
func (s *Service) upsert(ctx context.Context, tx pgx.Tx, device uuid.UUID, rows []row, force bool) (bool, error) {
	pending := false
	for _, r := range rows {
		chain, err := json.Marshal(agentproto.EncodeTrustChain(r.chain))
		if err != nil {
			return false, err
		}
		add, err := json.Marshal(agentproto.EncodeTrustChain(r.addCerts))
		if err != nil {
			return false, err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO device_tls_trust AS t (device_id, scope, host, purpose, chain, chain_digest, add_certs, chain_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (device_id, scope, host, purpose) DO UPDATE SET
				chain = EXCLUDED.chain, chain_digest = EXCLUDED.chain_digest, add_certs = EXCLUDED.add_certs, chain_id = EXCLUDED.chain_id,
				state = 'pending', error = '', request_id = NULL, sent_at = NULL, checked_at = NULL, requested_at = now()
			WHERE $9 OR t.chain_digest <> EXCLUDED.chain_digest OR t.add_certs <> EXCLUDED.add_certs`,
			device, r.scope, r.host, r.purpose, chain, r.digest(), add, r.chainID(), force)
		if err != nil {
			return false, err
		}
		if tag.RowsAffected() > 0 {
			pending = true
		}
	}
	return pending, nil
}

// state is device_tls_state.
type state struct {
	exists  bool
	origin  string
	sha     string
	capable bool
	refused string
	refID   string
}

func (s *Service) loadState(ctx context.Context, tx pgx.Tx, device uuid.UUID) (st state, err error) {
	err = tx.QueryRow(ctx, `SELECT origin, agent_sha256, capable, refused, refused_id FROM device_tls_state WHERE device_id = $1`, device).
		Scan(&st.origin, &st.sha, &st.capable, &st.refused, &st.refID)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, nil
	}
	st.exists = err == nil
	return st, err
}

// Heartbeat handles what a heartbeat says of trust and returns the instruction
// for the answer, nil when there is none. It is never a reason to fail the
// heartbeat: a failure is logged and the device is asked again at its next.
func (s *Service) Heartbeat(ctx context.Context, d Device, b Beat) *agentproto.SignedTrust {
	if len(s.key) == 0 || !devscope.Allowed(d.Org) {
		return nil
	}
	capable := slices.Contains(b.Caps, agentproto.CapTrust)
	var out *agentproto.SignedTrust
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		st, err := s.loadState(ctx, tx, d.ID)
		if err != nil {
			return err
		}
		if !capable && !st.capable && b.Report == nil {
			return nil // an older agent, or a first heartbeat: nothing to say
		}
		if !capable && st.capable {
			// A rollback to a build that does not understand them: nothing is
			// sent until a build that does reports it.
			if _, err := tx.Exec(ctx, `UPDATE device_tls_state SET capable = false, agent_sha256 = $2, updated_at = now() WHERE device_id = $1`,
				d.ID, truncate(b.AgentSHA256, 64)); err != nil {
				return err
			}
		}
		rebuilt := st.exists && st.sha != "" && b.AgentSHA256 != "" && st.sha != b.AgentSHA256
		justCapable := capable && !st.capable
		if capable {
			if err := s.saveState(ctx, tx, d.ID, b); err != nil {
				return err
			}
		}
		if b.Report != nil {
			if err := s.report(ctx, tx, d, b, st); err != nil {
				return err
			}
		}
		if !capable {
			return nil
		}
		// Re-checked whenever it could change: the first time this build says
		// it can, when the build changed, and when a chain changed (its digest
		// differs from the question asked).
		if err := s.recheck(ctx, tx, d, b.Origin, rebuilt || justCapable); err != nil {
			return err
		}
		out, err = s.instruction(ctx, tx, d, b.Origin)
		return err
	})
	if err != nil {
		s.log.Warn("tlstrust: handling a heartbeat failed", "error", err, "device_id", d.ID)
		return nil
	}
	return out
}

func (s *Service) saveState(ctx context.Context, tx pgx.Tx, device uuid.UUID, b Beat) error {
	_, err := tx.Exec(ctx, `INSERT INTO device_tls_state AS t (device_id, origin, agent_sha256, capable, capable_at)
		VALUES ($1, $2, $3, true, now())
		ON CONFLICT (device_id) DO UPDATE SET origin = EXCLUDED.origin, agent_sha256 = EXCLUDED.agent_sha256,
			capable_at = CASE WHEN t.capable THEN t.capable_at ELSE now() END, capable = true, updated_at = now()
		WHERE t.origin <> EXCLUDED.origin OR t.agent_sha256 <> EXCLUDED.agent_sha256 OR NOT t.capable`,
		device, truncate(b.Origin, 253), truncate(b.AgentSHA256, 64))
	return err
}

// recheck asks the device about the chains served for its origin, where they
// are new, changed, or the build is.
func (s *Service) recheck(ctx context.Context, tx pgx.Tx, d Device, origin string, force bool) error {
	src := s.source()
	if src == nil || !validOrigin(origin) {
		return nil
	}
	var rows []row
	for _, c := range src.Chains(origin) {
		if len(c.DER) == 0 {
			continue
		}
		rows = append(rows, row{scope: agentproto.TrustScopeAgent, host: origin, purpose: c.Purpose, chain: c.DER})
	}
	if len(rows) > 0 {
		if _, err := s.upsert(ctx, tx, d.ID, rows, force); err != nil {
			return err
		}
		if err := prune(ctx, tx, d.ID, agentproto.TrustScopeAgent, origin, rows); err != nil {
			return err
		}
	}
	s.mu.RLock()
	find := s.easyPatchHost
	s.mu.RUnlock()
	if find == nil {
		return nil
	}
	host := find(ctx, d.ID)
	if host == "" || !validOrigin(host) {
		return nil
	}
	var prows []row
	for _, c := range src.Chains(host) {
		if len(c.DER) > 0 {
			prows = append(prows, row{scope: agentproto.TrustScopeEasyPatch, host: host, purpose: c.Purpose, chain: c.DER})
		}
	}
	if len(prows) > 0 {
		if _, err := s.upsert(ctx, tx, d.ID, prows, force); err != nil {
			return err
		}
		return prune(ctx, tx, d.ID, agentproto.TrustScopeEasyPatch, host, prows)
	}
	return nil
}

// prune drops the served and fallback rows of a host the source no longer
// lists (a name that lost its fallback). A move's target rows are never
// touched here.
func prune(ctx context.Context, tx pgx.Tx, device uuid.UUID, scope, host string, keep []row) error {
	purposes := make([]string, len(keep))
	for i, r := range keep {
		purposes[i] = r.purpose
	}
	_, err := tx.Exec(ctx, `DELETE FROM device_tls_trust WHERE device_id = $1 AND scope = $2 AND host = $3
		AND purpose IN ('served', 'fallback') AND NOT (purpose = ANY ($4))`, device, scope, host, purposes)
	return err
}

// validOrigin: trust instructions are for DNS names, never an IP address.
func validOrigin(h string) bool {
	if h == "" || h != strings.ToLower(h) {
		return false
	}
	_, err := netip.ParseAddr(h)
	return err != nil && !strings.ContainsAny(h, ":/ ")
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// instruction signs the instruction for a device's pending rows.
func (s *Service) instruction(ctx context.Context, tx pgx.Tx, d Device, origin string) (*agentproto.SignedTrust, error) {
	rows, err := tx.Query(ctx, `SELECT scope, host, purpose, chain, add_certs, chain_id, request_id FROM device_tls_trust
		WHERE device_id = $1 AND state = 'pending' ORDER BY scope, host, purpose, chain_id`, d.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	p := agentproto.TrustPayload{V: agentproto.TrustPayloadVersion, DeviceID: d.ID.String(), Origin: origin}
	var adds []string
	sent := map[string]string{} // chain id -> request id it carried
	n := 0
	for rows.Next() {
		var scope, host, purpose, chainID string
		var chainJSON, addJSON []byte
		var reqID *string
		if err := rows.Scan(&scope, &host, &purpose, &chainJSON, &addJSON, &chainID, &reqID); err != nil {
			return nil, err
		}
		var chain, add []string
		if json.Unmarshal(chainJSON, &chain) != nil || json.Unmarshal(addJSON, &add) != nil {
			continue
		}
		c := agentproto.TrustChain{ID: chainID, Purpose: purpose, Chain: chain}
		switch {
		case scope == agentproto.TrustScopeAgent && host == origin:
			p.Chains = append(p.Chains, c)
			for _, a := range add {
				if !slices.Contains(adds, a) {
					adds = append(adds, a)
				}
			}
		case scope == agentproto.TrustScopeEasyPatch && (p.EasyPatchHost == "" || p.EasyPatchHost == host):
			p.EasyPatchHost = host
			p.EasyPatchChains = append(p.EasyPatchChains, c)
		default:
			continue // a host the device no longer uses
		}
		if reqID != nil {
			sent[chainID] = *reqID
		}
		if n++; n >= agentproto.MaxTrustChains {
			break
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if len(p.Chains)+len(p.EasyPatchChains) == 0 {
		return nil, nil
	}
	if len(adds) > agentproto.MaxTrustAddCerts {
		adds = adds[:agentproto.MaxTrustAddCerts]
	}
	p.AddCerts = adds
	p.ID = requestID(p)
	now := s.now().UTC()
	p.IssuedAt, p.ExpiresAt = now, now.Add(agentproto.TrustValid)
	signed, err := agentproto.SignTrust(s.key, p)
	if err != nil {
		// A chain too large or broken to send: logged, and the rest of the
		// heartbeat goes on.
		s.log.Error("tlstrust: signing a trust instruction failed", "error", err, "device_id", d.ID)
		return nil, nil
	}
	for _, c := range append(slices.Clone(p.Chains), p.EasyPatchChains...) {
		if sent[c.ID] == p.ID {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE device_tls_trust SET request_id = $3, sent_at = $4
			WHERE device_id = $1 AND chain_id = $2 AND state = 'pending'`, d.ID, c.ID, p.ID, now); err != nil {
			return nil, err
		}
	}
	return &signed, nil
}

// requestID names an instruction by what it asks, so that the same question
// keeps its ID (the agent answers a known ID from memory and carries it out
// once) and a different one gets another.
func requestID(p agentproto.TrustPayload) string {
	h := sha256.New()
	write := func(parts ...string) {
		for _, s := range parts {
			h.Write([]byte(s))
			h.Write([]byte{0})
		}
	}
	write(p.DeviceID, p.Origin, p.EasyPatchHost)
	write(p.AddCerts...)
	for _, c := range append(slices.Clone(p.Chains), p.EasyPatchChains...) {
		write(c.ID, c.Purpose)
		write(c.Chain...)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// report records an agent's answer to an instruction.
func (s *Service) report(ctx context.Context, tx pgx.Tx, d Device, b Beat, st state) error {
	r := b.Report
	if r.ID == "" || len(r.ID) > 64 || len(r.Results) > agentproto.MaxTrustResults {
		return nil
	}
	trusts := ""
	switch r.Trusts {
	case "system", "ca-file", "system+ca-file":
		trusts = r.Trusts
	}
	if r.Refused != "" {
		// The agent did not carry it out: the rows stay pending and are sent
		// again. Audited once per instruction and reason.
		reason := truncate(r.Refused, agentproto.MaxTrustError)
		if st.refID == r.ID && st.refused == reason {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE device_tls_state SET refused = $2, refused_id = $3, trusts = $4, updated_at = now() WHERE device_id = $1`,
			d.ID, reason, r.ID, trusts); err != nil {
			return err
		}
		return s.auditReport(ctx, tx, d, b, audit.Failure, map[string]any{"origin": b.Origin, "request": r.ID, "refused": reason})
	}
	var results []map[string]any
	for _, res := range r.Results {
		if res.Scope != agentproto.TrustScopeAgent && res.Scope != agentproto.TrustScopeEasyPatch {
			continue
		}
		state, errText := "passed", ""
		if !res.OK {
			state, errText = "failed", truncate(strings.Join(strings.Fields(res.Error), " "), agentproto.MaxTrustError)
		}
		var host, purpose string
		err := tx.QueryRow(ctx, `UPDATE device_tls_trust SET state = $5, error = $6, checked_at = now()
			WHERE device_id = $1 AND scope = $2 AND chain_id = $3 AND request_id = $4 AND state = 'pending'
			RETURNING host, purpose`, d.ID, res.Scope, res.Chain, r.ID, state, errText).Scan(&host, &purpose)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // not asked, answered already, or asked again since
		}
		if err != nil {
			return err
		}
		results = append(results, map[string]any{"scope": res.Scope, "host": host, "purpose": purpose, "ok": res.OK, "error": errText})
	}
	if _, err := tx.Exec(ctx, `UPDATE device_tls_state SET trusts = $2, widened = $3, reported_at = now(), refused = '', refused_id = '', updated_at = now()
		WHERE device_id = $1`, d.ID, trusts, r.Widened); err != nil {
		return err
	}
	if len(results) == 0 {
		return nil
	}
	sort.Slice(results, func(i, j int) bool {
		return fmt.Sprint(results[i]["scope"], results[i]["host"], results[i]["purpose"]) < fmt.Sprint(results[j]["scope"], results[j]["host"], results[j]["purpose"])
	})
	return s.auditReport(ctx, tx, d, b, audit.Success, map[string]any{
		"origin": b.Origin, "request": r.ID, "results": results, "widened": r.Widened, "trusts": trusts,
	})
}

func (s *Service) auditReport(ctx context.Context, tx pgx.Tx, d Device, b Beat, outcome audit.Outcome, details map[string]any) error {
	return s.audit.Write(ctx, tx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: d.Hostname, SourceIP: b.IP},
		Action: "device.tls_trust", OrganizationID: d.Org, SiteID: d.Site, DeviceID: d.ID,
		TargetType: "device", TargetID: d.ID.String(), Outcome: outcome, Details: details,
	})
}

// EncodeDER is a helper for callers that hold certificates as DER.
func EncodeDER(der []byte) string { return base64.StdEncoding.EncodeToString(der) }
