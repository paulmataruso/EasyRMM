package agents

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Enrollment with approval (ADR-0024): an approval token is an install
// command for any site. Devices installed with it wait as enrollment
// requests until someone who manages enrollment everywhere approves them
// into a site, or rejects them.

// Approval limits.
const (
	// MaxWaiting bounds the requests waiting for a decision, so a leaked
	// install command cannot fill the database.
	MaxWaiting = 10_000
	// MaxDecide bounds the requests one approval or rejection covers.
	MaxDecide = 500
	// MaxRequests bounds one list response.
	MaxRequests = 2000
	// RequestOnline is how recently a waiting agent must have asked to
	// count as running: it asks again at least every ApprovalWait.
	RequestOnline = 2 * time.Minute
	// Waiting requests whose agent stopped asking, and rejected ones, are
	// forgotten after these.
	forgetWaiting  = 7 * 24 * time.Hour
	forgetRejected = 30 * 24 * time.Hour
	// retrySeconds is how long an agent waits before asking again when the
	// server answered without holding the request open.
	retrySeconds = 5
)

var (
	// ErrRejected is an enrollment request someone rejected.
	ErrRejected = errors.New("agents: enrollment rejected")
	// ErrTooManyWaiting means MaxWaiting requests wait already.
	ErrTooManyWaiting = errors.New("agents: too many devices waiting for approval")

	errNoApprovalToken = errors.New("agents: not an approval token")
)

// waitHub wakes enrollments waiting for a decision on this instance, by
// public key (base64).
type waitHub struct {
	mu      sync.Mutex
	waiters map[string]map[chan struct{}]struct{}
	done    chan struct{}
	closed  bool
}

func newWaitHub() *waitHub {
	return &waitHub{waiters: map[string]map[chan struct{}]struct{}{}, done: make(chan struct{})}
}

func (h *waitHub) subscribe(key string) chan struct{} {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.waiters[key] == nil {
		h.waiters[key] = map[chan struct{}]struct{}{}
	}
	h.waiters[key][ch] = struct{}{}
	return ch
}

func (h *waitHub) unsubscribe(key string, ch chan struct{}) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.waiters[key], ch)
	if len(h.waiters[key]) == 0 {
		delete(h.waiters, key)
	}
}

func (h *waitHub) notify(keys ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, k := range keys {
		for ch := range h.waiters[k] {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	}
}

func (h *waitHub) close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.closed {
		h.closed = true
		close(h.done)
	}
}

// Close ends the enrollments waiting for a decision, for shutdown: they
// answer that the device still waits.
func (s *Service) Close() { s.waits.close() }

// pending is the answer to a device that waits.
func pending(key []byte, retry int) *agentproto.EnrollResponse {
	return &agentproto.EnrollResponse{Pending: &agentproto.EnrollPending{Code: agentproto.DeviceCode(key), RetrySeconds: retry}}
}

// askApproval handles an enrollment with an approval token: a device
// asking again learns its request's state; a new one is recorded. It
// returns errNoApprovalToken when the token is not one.
func (s *Service) askApproval(ctx context.Context, tx pgx.Tx, ip netip.Addr, hash, key []byte, f facts, again bool) (resp *agentproto.EnrollResponse, fresh bool, err error) {
	var tokenID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM approval_tokens WHERE token_hash = $1`, hash).Scan(&tokenID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, errNoApprovalToken
	}
	if err != nil {
		return nil, false, err
	}

	var (
		reqID, reqToken uuid.UUID
		state           string
		deviceID        *uuid.UUID
	)
	err = tx.QueryRow(ctx, `SELECT id, token_id, state, device_id FROM enrollment_requests WHERE public_key = $1 FOR UPDATE`, key).
		Scan(&reqID, &reqToken, &state, &deviceID)
	switch {
	case err == nil:
		// The same key with another token is not this device's request.
		if reqToken != tokenID {
			return nil, false, ErrTokenInvalid
		}
		// A waiting agent asks again all the time; a whole office may wait
		// behind one address, so these are limited per device.
		if !again && !s.polls.Allow(base64.StdEncoding.EncodeToString(key)) {
			return nil, false, ErrRateLimited
		}
		switch state {
		case "approved":
			return &agentproto.EnrollResponse{DeviceID: deviceID.String()}, false, nil
		case "rejected":
			return nil, false, ErrRejected
		}
		// Still waiting: what the console shows stays current. Expired or
		// revoked tokens do not stop a device that asked in time.
		_, err := tx.Exec(ctx, `UPDATE enrollment_requests SET last_seen_at = now(), hostname = $2, os_description = $3, platform = $4,
			agent_version = $5, agent_arch = $6, source_ip = $7 WHERE id = $1`,
			reqID, f.hostname, f.os, f.platform, f.version, f.arch, ip.String())
		return pending(key, retrySeconds), false, err
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, false, err
	}

	// A new device.
	if !s.enroll.Allow(auth.LimitKey(ip)) {
		return nil, false, ErrRateLimited
	}
	var (
		name    string
		expires time.Time
		maxUses *int
		uses    int
		revoked bool
	)
	if err := tx.QueryRow(ctx, `SELECT name, expires_at, max_uses, uses, revoked_at IS NOT NULL FROM approval_tokens WHERE id = $1 FOR UPDATE`, tokenID).
		Scan(&name, &expires, &maxUses, &uses, &revoked); err != nil {
		return nil, false, err
	}
	if st := tokenStatus(revoked, expires, maxUses, uses, s.now()); st != TokenActive {
		s.log.Info("agent enrollment refused", "approval_token_id", tokenID, "token_status", st, "ip", ip.String(), "hostname", f.hostname)
		return nil, false, ErrTokenInvalid
	}
	var inUse bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM devices WHERE agent_public_key = $1)`, key).Scan(&inUse); err != nil {
		return nil, false, err
	}
	if inUse {
		return nil, false, ErrKeyInUse
	}
	var waiting int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM enrollment_requests WHERE state = 'pending'`).Scan(&waiting); err != nil {
		return nil, false, err
	}
	if waiting >= MaxWaiting {
		return nil, false, ErrTooManyWaiting
	}
	err = tx.QueryRow(ctx, `INSERT INTO enrollment_requests (token_id, public_key, hostname, os_description, platform, agent_version, agent_arch, source_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		tokenID, key, f.hostname, f.os, f.platform, f.version, f.arch, ip.String()).Scan(&reqID)
	if database.IsUniqueViolation(err) {
		// The same agent asking twice at once: the other request won.
		return nil, false, ErrRateLimited
	}
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE approval_tokens SET uses = uses + 1, last_used_at = now() WHERE id = $1`, tokenID); err != nil {
		return nil, false, err
	}
	code := agentproto.DeviceCode(key)
	s.log.Info("agent waits for approval", "request_id", reqID, "hostname", f.hostname, "code", code, "approval_token_id", tokenID)
	return pending(key, retrySeconds), true, s.audit.Write(ctx, tx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorAgent, ID: reqID, Label: f.hostname, SourceIP: ip},
		Action: "enrollment_request.create", Outcome: audit.Success,
		TargetType: "enrollment_request", TargetID: reqID.String(),
		Details: map[string]any{
			"device": f.hostname, "code": code, "platform": f.platform, "agentVersion": f.version,
			"token": name, "tokenId": tokenID.String(),
		},
	})
}

// requireApprover checks that the caller manages enrollment everywhere:
// waiting devices belong to no organization yet.
func requireApprover(c access.Caller) error {
	return c.RequireGlobal(rbac.PermEnrollManage)
}

// ApprovalToken is an approval token as the console shows it. The secret
// is only returned once, by CreateApprovalToken.
type ApprovalToken struct {
	ID            uuid.UUID   `json:"id"`
	Name          string      `json:"name"`
	ExpiresAt     time.Time   `json:"expiresAt"`
	MaxUses       *int        `json:"maxUses"`
	Uses          int         `json:"uses"`
	Waiting       int         `json:"waiting"`
	CreatedByName string      `json:"createdByName,omitempty"`
	CreatedAt     time.Time   `json:"createdAt"`
	LastUsedAt    *time.Time  `json:"lastUsedAt"`
	RevokedAt     *time.Time  `json:"revokedAt"`
	Status        TokenStatus `json:"status"`
}

// ApprovalTokenInput describes a new approval token.
type ApprovalTokenInput struct {
	Name          string `json:"name"`
	ExpiresInDays int    `json:"expiresInDays"`
	// MaxUses limits how many devices can ask to enroll; nil means no limit.
	MaxUses *int `json:"maxUses"`
}

// NewApprovalToken is a created approval token and its secret, shown once.
type NewApprovalToken struct {
	Token  *ApprovalToken `json:"token"`
	Secret string         `json:"secret"`
}

//nolint:gosec // column names, not credentials
const approvalTokenSelect = `SELECT t.id, t.name, t.expires_at, t.max_uses, t.uses,
		(SELECT count(*) FROM enrollment_requests r WHERE r.token_id = t.id AND r.state = 'pending'),
		coalesce(u.display_name, ''), t.created_at, t.last_used_at, t.revoked_at
	FROM approval_tokens t LEFT JOIN users u ON u.id = t.created_by`

func (s *Service) scanApprovalToken(row pgx.Row) (*ApprovalToken, error) {
	var t ApprovalToken
	if err := row.Scan(&t.ID, &t.Name, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.Waiting, &t.CreatedByName, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
		return nil, err
	}
	t.Status = tokenStatus(t.RevokedAt != nil, t.ExpiresAt, t.MaxUses, t.Uses, s.now())
	return &t, nil
}

// CreateApprovalToken creates an install command for any site whose
// devices wait for approval.
func (s *Service) CreateApprovalToken(ctx context.Context, c access.Caller, in ApprovalTokenInput) (*NewApprovalToken, error) {
	if err := requireApprover(c); err != nil {
		return nil, err
	}
	norm := TokenInput{Name: in.Name, ExpiresInDays: in.ExpiresInDays, MaxUses: in.MaxUses}
	if err := norm.normalize(); err != nil {
		return nil, err
	}
	secret, hash, err := newTokenSecret()
	if err != nil {
		return nil, err
	}
	var createdBy *uuid.UUID
	if c.Principal != nil {
		createdBy = &c.Principal.UserID
	}
	expires := s.now().Add(time.Duration(norm.ExpiresInDays) * 24 * time.Hour)
	var id uuid.UUID
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO approval_tokens (name, token_hash, expires_at, max_uses, created_by)
			VALUES ($1, $2, $3, $4, $5) RETURNING id`, norm.Name, hash, expires, norm.MaxUses, createdBy).Scan(&id); err != nil {
			return err
		}
		details := map[string]any{"name": norm.Name, "expiresAt": expires.UTC().Format(time.RFC3339)}
		if norm.MaxUses != nil {
			details["maxUses"] = *norm.MaxUses
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "approval_token.create", Outcome: audit.Success,
			TargetType: "approval_token", TargetID: id.String(), Details: details})
	})
	if err != nil {
		return nil, err
	}
	t, err := s.GetApprovalToken(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return &NewApprovalToken{Token: t, Secret: secret}, nil
}

// GetApprovalToken returns one approval token.
func (s *Service) GetApprovalToken(ctx context.Context, c access.Caller, id uuid.UUID) (*ApprovalToken, error) {
	if err := requireApprover(c); err != nil {
		return nil, err
	}
	var t *ApprovalToken
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		t, err = s.scanApprovalToken(tx.QueryRow(ctx, approvalTokenSelect+` WHERE t.id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	return t, err
}

// ListApprovalTokens returns approval tokens, newest first; with active,
// only those that can still bring in devices.
func (s *Service) ListApprovalTokens(ctx context.Context, c access.Caller, active bool) ([]*ApprovalToken, error) {
	if err := requireApprover(c); err != nil {
		return nil, err
	}
	out := []*ApprovalToken{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, approvalTokenSelect+`
			WHERE NOT $1 OR (t.revoked_at IS NULL AND t.expires_at > now() AND (t.max_uses IS NULL OR t.uses < t.max_uses))
			ORDER BY t.created_at DESC, t.id LIMIT $2`, active, MaxTokens)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := s.scanApprovalToken(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// RevokeApprovalToken stops a token from bringing in more devices. Devices
// already waiting can still be approved or rejected.
func (s *Service) RevokeApprovalToken(ctx context.Context, c access.Caller, id uuid.UUID) (*ApprovalToken, error) {
	t, err := s.GetApprovalToken(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if t.RevokedAt != nil {
		return t, nil
	}
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE approval_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "approval_token.revoke", Outcome: audit.Success,
			TargetType: "approval_token", TargetID: id.String(), Details: map[string]any{"name": t.Name, "uses": t.Uses}})
	})
	if err != nil {
		return nil, err
	}
	return s.GetApprovalToken(ctx, c, id)
}

// Request is a device that asked to enroll with an approval token.
type Request struct {
	ID           uuid.UUID `json:"id"`
	Code         string    `json:"code"`
	Hostname     string    `json:"hostname"`
	OS           string    `json:"os"`
	Platform     string    `json:"platform"`
	Arch         string    `json:"arch"`
	AgentVersion string    `json:"agentVersion"`
	SourceIP     string    `json:"sourceIp,omitempty"`
	State        string    `json:"state"`
	TokenID      uuid.UUID `json:"tokenId"`
	TokenName    string    `json:"tokenName"`
	CreatedAt    time.Time `json:"createdAt"`
	LastSeenAt   time.Time `json:"lastSeenAt"`
	// Online is an agent that asked within RequestOnline.
	Online        bool       `json:"online"`
	DecidedAt     *time.Time `json:"decidedAt,omitempty"`
	DecidedByName string     `json:"decidedByName,omitempty"`
	DeviceID      *uuid.UUID `json:"deviceId,omitempty"`
	// Matches are enrolled devices with the same host name: approving
	// would add another, as when a machine was reinstalled.
	Matches []RequestMatch `json:"matches"`
}

// RequestMatch is an enrolled device with a waiting device's host name.
type RequestMatch struct {
	DeviceID         uuid.UUID `json:"deviceId"`
	Name             string    `json:"name"`
	OrganizationName string    `json:"organizationName"`
	SiteName         string    `json:"siteName"`
}

// RequestList is the requests of one state and how many wait.
type RequestList struct {
	Items   []*Request `json:"items"`
	Waiting int        `json:"waiting"`
}

// RequestStates are the states ListRequests accepts.
var RequestStates = []string{"pending", "rejected"}

// ListRequests returns the requests in a state, newest first.
func (s *Service) ListRequests(ctx context.Context, c access.Caller, state string) (*RequestList, error) {
	if err := requireApprover(c); err != nil {
		return nil, err
	}
	if !slices.Contains(RequestStates, state) {
		return nil, apperr.Invalid("state", "Choose pending or rejected.")
	}
	out := &RequestList{Items: []*Request{}}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.id, r.public_key, r.hostname, r.os_description, r.platform, r.agent_arch, r.agent_version,
				coalesce(host(r.source_ip), ''), r.state, r.token_id, t.name, r.created_at, r.last_seen_at, r.decided_at,
				coalesce(u.display_name, ''), r.device_id
			FROM enrollment_requests r
			JOIN approval_tokens t ON t.id = r.token_id
			LEFT JOIN users u ON u.id = r.decided_by
			WHERE r.state = $1
			ORDER BY coalesce(r.decided_at, r.created_at) DESC, r.id LIMIT $2`, state, MaxRequests)
		if err != nil {
			return err
		}
		defer rows.Close()
		byHost := map[string][]*Request{}
		for rows.Next() {
			var r Request
			var key []byte
			if err := rows.Scan(&r.ID, &key, &r.Hostname, &r.OS, &r.Platform, &r.Arch, &r.AgentVersion, &r.SourceIP, &r.State,
				&r.TokenID, &r.TokenName, &r.CreatedAt, &r.LastSeenAt, &r.DecidedAt, &r.DecidedByName, &r.DeviceID); err != nil {
				return err
			}
			r.Code = agentproto.DeviceCode(key)
			r.Online = r.State == "pending" && s.now().Sub(r.LastSeenAt) < RequestOnline
			r.Matches = []RequestMatch{}
			out.Items = append(out.Items, &r)
			h := strings.ToLower(r.Hostname)
			byHost[h] = append(byHost[h], &r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM enrollment_requests WHERE state = 'pending'`).Scan(&out.Waiting); err != nil {
			return err
		}
		if len(byHost) == 0 {
			return nil
		}
		hosts := make([]string, 0, len(byHost))
		for h := range byHost {
			hosts = append(hosts, h)
		}
		rows, err = tx.Query(ctx, `SELECT d.id, d.name, lower(d.hostname), o.name, si.name
			FROM devices d JOIN sites si ON si.id = d.site_id JOIN organizations o ON o.id = d.organization_id
			WHERE lower(d.hostname) = ANY ($1) OR lower(d.name) = ANY ($1)
			ORDER BY d.name, d.id`, hosts)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var m RequestMatch
			var host string
			if err := rows.Scan(&m.DeviceID, &m.Name, &host, &m.OrganizationName, &m.SiteName); err != nil {
				return err
			}
			for _, h := range []string{host, strings.ToLower(m.Name)} {
				for _, r := range byHost[h] {
					if len(r.Matches) < 5 && !slices.ContainsFunc(r.Matches, func(x RequestMatch) bool { return x.DeviceID == m.DeviceID }) {
						r.Matches = append(r.Matches, m)
					}
				}
			}
		}
		return rows.Err()
	})
	return out, err
}

// Waiting returns how many devices wait for approval, or 0 for callers
// who cannot approve them.
func (s *Service) Waiting(ctx context.Context, c access.Caller) (int, error) {
	if !c.CanGlobal(rbac.PermEnrollManage) {
		return 0, nil
	}
	var n int
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM enrollment_requests WHERE state = 'pending'`).Scan(&n)
	})
	return n, err
}

// ApproveInput approves waiting devices into a site.
type ApproveInput struct {
	IDs           []uuid.UUID `json:"ids"`
	SiteID        uuid.UUID   `json:"siteId"`
	DeviceGroupID *uuid.UUID  `json:"deviceGroupId"`
}

// Decision reports which requests a decision covered. Skipped requests were
// decided by someone else meanwhile, or are gone.
type Decision struct {
	Decided []uuid.UUID `json:"decided"`
	// Devices are the devices approval created, in the order of Decided.
	Devices []uuid.UUID `json:"devices,omitempty"`
	Skipped []uuid.UUID `json:"skipped"`
}

func checkIDs(ids []uuid.UUID) error {
	if len(ids) == 0 || len(ids) > MaxDecide {
		return apperr.Invalid("ids", "Choose between 1 and 500 devices.")
	}
	return nil
}

// Approve creates the devices of waiting requests in a site, named after
// their host names, and lets their agents in.
func (s *Service) Approve(ctx context.Context, c access.Caller, in ApproveInput) (*Decision, error) {
	if err := requireApprover(c); err != nil {
		return nil, err
	}
	if err := checkIDs(in.IDs); err != nil {
		return nil, err
	}
	// The site as the database has it: its id is what the log names, not
	// the one the client sent.
	var siteID, orgID uuid.UUID
	var orgName, siteName string
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT s.id, s.organization_id, o.name, s.name FROM sites s JOIN organizations o ON o.id = s.organization_id WHERE s.id = $1`,
			in.SiteID).Scan(&siteID, &orgID, &orgName, &siteName)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.Invalid("siteId", "Choose a site.")
		}
		if err != nil || in.DeviceGroupID == nil {
			return err
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM device_groups WHERE id = $1 AND site_id = $2)`, in.DeviceGroupID, in.SiteID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return apperr.Invalid("deviceGroupId", "Choose a device group of this site.")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := c.Require(rbac.PermEnrollManage, rbac.Site(orgID, in.SiteID)); err != nil {
		return nil, err
	}

	out := &Decision{Decided: []uuid.UUID{}, Skipped: []uuid.UUID{}}
	var keys []string
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT r.id, r.public_key, r.hostname, r.os_description, r.platform, r.agent_version, r.agent_arch,
				r.last_seen_at, r.token_id, t.name
			FROM enrollment_requests r JOIN approval_tokens t ON t.id = r.token_id
			WHERE r.id = ANY ($1) AND r.state = 'pending'
			ORDER BY r.hostname, r.id FOR UPDATE OF r`, in.IDs)
		if err != nil {
			return err
		}
		type req struct {
			id, tokenID                   uuid.UUID
			key                           []byte
			host, os, platform, ver, arch string
			lastSeen                      time.Time
			tokenName                     string
		}
		var reqs []req
		for rows.Next() {
			var r req
			if err := rows.Scan(&r.id, &r.key, &r.host, &r.os, &r.platform, &r.ver, &r.arch, &r.lastSeen, &r.tokenID, &r.tokenName); err != nil {
				return err
			}
			reqs = append(reqs, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range reqs {
			var deviceID uuid.UUID
			// The device's key is its identity; the request held it alone,
			// so the insert cannot collide.
			if err := tx.QueryRow(ctx, `INSERT INTO devices (organization_id, site_id, device_group_id, name, hostname, os_description, platform,
					agent_public_key, agent_version, agent_arch, agent_last_seen_at, enrolled_at)
				VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, $10, now()) RETURNING id`,
				orgID, in.SiteID, in.DeviceGroupID, r.host, r.os, r.platform, r.key, r.ver, r.arch, r.lastSeen).Scan(&deviceID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE enrollment_requests SET state = 'approved', device_id = $2, decided_by = $3, decided_at = now() WHERE id = $1`,
				r.id, deviceID, userID(c)); err != nil {
				return err
			}
			details := map[string]any{
				"device": r.host, "code": agentproto.DeviceCode(r.key), "platform": r.platform, "agentVersion": r.ver,
				"organization": orgName, "site": siteName, "token": r.tokenName, "tokenId": r.tokenID.String(), "requestId": r.id.String(),
			}
			if in.DeviceGroupID != nil {
				details["deviceGroupId"] = in.DeviceGroupID.String()
			}
			if err := s.audit.Write(ctx, tx, audit.Event{
				Actor: c.Actor, Action: "enrollment_request.approve", Outcome: audit.Success,
				OrganizationID: orgID, SiteID: in.SiteID, DeviceID: deviceID, TargetType: "device", TargetID: deviceID.String(),
				Details: details,
			}); err != nil {
				return err
			}
			out.Decided = append(out.Decided, r.id)
			out.Devices = append(out.Devices, deviceID)
			keys = append(keys, base64.StdEncoding.EncodeToString(r.key))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Skipped = skipped(in.IDs, out.Decided)
	s.waits.notify(keys...)
	s.log.Info("devices approved", "count", len(out.Decided), "site_id", siteID)
	return out, nil
}

// Reject turns waiting devices away. Their agents stop asking.
func (s *Service) Reject(ctx context.Context, c access.Caller, ids []uuid.UUID) (*Decision, error) {
	if err := requireApprover(c); err != nil {
		return nil, err
	}
	if err := checkIDs(ids); err != nil {
		return nil, err
	}
	out := &Decision{Decided: []uuid.UUID{}, Skipped: []uuid.UUID{}}
	var keys []string
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE enrollment_requests r SET state = 'rejected', decided_by = $2, decided_at = now()
			FROM approval_tokens t
			WHERE t.id = r.token_id AND r.id = ANY ($1) AND r.state = 'pending'
			RETURNING r.id, r.public_key, r.hostname, r.platform, coalesce(host(r.source_ip), ''), t.name, t.id`, ids, userID(c))
		if err != nil {
			return err
		}
		type rejected struct {
			id, tokenID        uuid.UUID
			key                []byte
			host, platform, ip string
			tokenName          string
		}
		var done []rejected
		for rows.Next() {
			var r rejected
			if err := rows.Scan(&r.id, &r.key, &r.host, &r.platform, &r.ip, &r.tokenName, &r.tokenID); err != nil {
				return err
			}
			done = append(done, r)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range done {
			details := map[string]any{"device": r.host, "code": agentproto.DeviceCode(r.key), "platform": r.platform, "token": r.tokenName, "tokenId": r.tokenID.String()}
			if r.ip != "" {
				details["sourceIp"] = r.ip
			}
			if err := s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "enrollment_request.reject", Outcome: audit.Success,
				TargetType: "enrollment_request", TargetID: r.id.String(), Details: details}); err != nil {
				return err
			}
			out.Decided = append(out.Decided, r.id)
			keys = append(keys, base64.StdEncoding.EncodeToString(r.key))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out.Skipped = skipped(ids, out.Decided)
	s.waits.notify(keys...)
	return out, nil
}

func skipped(asked, decided []uuid.UUID) []uuid.UUID {
	out := []uuid.UUID{}
	for _, id := range asked {
		if !slices.Contains(decided, id) && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

func userID(c access.Caller) *uuid.UUID {
	if c.Principal == nil {
		return nil
	}
	return &c.Principal.UserID
}

// cleanupRequests forgets requests nobody needs any more: waiting ones
// whose agent stopped asking, rejected ones after a while, and approved
// ones once the agent has picked up its device.
func cleanupRequests(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `DELETE FROM enrollment_requests r
		WHERE (r.state = 'pending' AND r.last_seen_at < now() - make_interval(secs => $1))
		   OR (r.state = 'rejected' AND r.decided_at < now() - make_interval(secs => $2))
		   OR (r.state = 'approved' AND EXISTS (SELECT 1 FROM devices d WHERE d.id = r.device_id AND d.agent_last_seen_at > r.decided_at))`,
		forgetWaiting.Seconds(), forgetRejected.Seconds())
	return err
}
