package quickassist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/qaticket"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Session states.
const (
	SessionRequested = "requested"
	SessionActive    = "active"
	SessionDeclined  = "declined"
	SessionEnded     = "ended"
	SessionLost      = "lost"
	SessionConverted = "converted"
)

// Timings and limits (ADR-0080).
const (
	RequestWait     = 10 * time.Minute
	MaxSessionLife  = 8 * time.Hour
	LostAfter       = 10 * time.Minute
	CleanupWait     = 10 * time.Minute
	WaitingCap      = 20
	MaxCodeFailures = 3
	Retention       = 30 * 24 * time.Hour
	// HeartbeatSeconds is how often a runner asks about its session.
	HeartbeatSeconds = 20
	maxReport        = 16 * 1024
)

// ErrTicket is a ticket the server does not accept; the answer is the
// same for every reason.
var ErrTicket = errors.New("quickassist: the ticket is not accepted")

var codePattern = regexp.MustCompile(`^[0-9]{6}$`)

// Facts are what the runner reports about its computer.
type Facts struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Platform string `json:"platform"`
	Version  string `json:"version"`
	Arch     string `json:"arch"`
	Elevated bool   `json:"elevated"`
}

// EnrollRequest is a runner's request to start a session. Code is the six
// digits its window shows; Consent is the user's click on Allow.
type EnrollRequest struct {
	Ticket    string `json:"ticket"` // base64 of the trailer
	PublicKey string `json:"publicKey"`
	Code      string `json:"code"`
	Consent   bool   `json:"consent"`
	Facts     Facts  `json:"facts"`
}

// EnrollResult is the answer to a runner.
type EnrollResult struct {
	DeviceID         string `json:"deviceId"`
	SessionID        string `json:"sessionId"`
	HeartbeatSeconds int    `json:"heartbeatSeconds"`
	Organization     string `json:"organization"`
}

func codeHash(session uuid.UUID, code string) []byte {
	h := sha256.Sum256(append(session[:], code...))
	return h[:]
}

func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// Enroll starts a session from a runner's ticket. The server believes
// nothing about consent beyond recording it: no remote control is allowed
// until a technician accepts.
func (s *Service) Enroll(ctx context.Context, ip netip.Addr, req EnrollRequest) (*EnrollResult, error) {
	if !s.enrolls.Allow(auth.LimitKey(ip)) {
		return nil, ErrRateLimited
	}
	raw, err := base64.StdEncoding.DecodeString(req.Ticket)
	if err != nil {
		return nil, ErrTicket
	}
	tk, err := qaticket.Parse(bytes.NewReader(raw), int64(len(raw)), s.PublicKey(), s.now())
	if err != nil || tk.Server != s.publicURL {
		return nil, ErrTicket
	}
	linkID, err := uuid.Parse(tk.Link)
	if err != nil {
		return nil, ErrTicket
	}
	key, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, apperr.Invalid("publicKey", "Send a base64 Ed25519 public key.")
	}
	if !codePattern.MatchString(req.Code) || !req.Consent {
		return nil, apperr.Invalid("code", "Send the six-digit code and the user's consent.")
	}
	f := req.Facts
	f.Hostname = clean(f.Hostname, 255)
	if f.Hostname == "" {
		f.Hostname = "unknown"
	}
	switch f.Platform {
	case "windows", "linux", "macos":
	default:
		f.Platform = "other"
	}
	f.OS, f.Version, f.Arch = clean(f.OS, 500), clean(f.Version, 64), clean(f.Arch, 32)

	var res *EnrollResult
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var l linkRow
		err := tx.QueryRow(ctx, `SELECT l.id, l.organization_id, l.site_id, l.kind, l.name, l.state, l.paused, l.test, o.name
			FROM quick_assist_links l JOIN organizations o ON o.id = l.organization_id WHERE l.id = $1 FOR UPDATE OF l`, linkID).
			Scan(&l.ID, &l.OrganizationID, &l.SiteID, &l.Kind, &l.Name, &l.State, &l.Paused, &l.Test, &l.orgName)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTicket
		}
		if err != nil {
			return err
		}
		// A one-time link was consumed by the download that made this
		// ticket and starts one session; a permanent link must be live.
		var sessions int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM quick_assist_sessions WHERE link_id = $1`, l.ID).Scan(&sessions); err != nil {
			return err
		}
		ok := !l.Paused && devscope.Allowed(l.OrganizationID)
		if l.Kind == KindOneTime {
			ok = ok && l.State == LinkUsed && sessions == 0
		} else {
			ok = ok && l.State == LinkActive
		}
		if !ok {
			return ErrTicket
		}
		siteID, err := s.qaSite(ctx, tx, l.OrganizationID)
		if err != nil {
			return err
		}
		// The queue is bounded: the oldest unanswered request makes room.
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = 'declined', end_reason = 'evicted', ended_at = now()
			WHERE id IN (SELECT id FROM quick_assist_sessions WHERE organization_id = $1 AND state = 'requested'
				ORDER BY requested_at DESC OFFSET $2)`, l.OrganizationID, WaitingCap-1); err != nil {
			return err
		}
		sid, did := uuid.New(), uuid.New()
		now := s.now()
		_, err = tx.Exec(ctx, `INSERT INTO devices (id, organization_id, site_id, name, hostname, os_description, platform,
				agent_public_key, agent_version, agent_arch, agent_last_seen_at, enrolled_at, quick_assist, origin_session_id)
			VALUES ($1, $2, $3, $4, $4, $5, $6, $7, $8, $9, now(), now(), true, NULL)`,
			did, l.OrganizationID, siteID, f.Hostname, f.OS, f.Platform, key, f.Version, f.Arch)
		if database.IsUniqueViolation(err) {
			return ErrTicket
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO quick_assist_sessions (id, link_id, organization_id, device_id, session_code_hash, elevated, consent_at, requested_at, source_ip, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9)`,
			sid, l.ID, l.OrganizationID, did, codeHash(sid, req.Code), f.Elevated, now, ip.String(), now.Add(MaxSessionLife)); err != nil {
			return err
		}
		res = &EnrollResult{DeviceID: did.String(), SessionID: sid.String(), HeartbeatSeconds: HeartbeatSeconds, Organization: l.orgName}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor:  audit.Actor{Type: audit.ActorAgent, ID: did, Label: f.Hostname, SourceIP: ip},
			Action: ActionRequest, OrganizationID: l.OrganizationID, SiteID: siteID, DeviceID: did,
			TargetType: "quick_assist_session", TargetID: sid.String(), Outcome: audit.Success,
			Details: map[string]any{"linkId": l.ID.String(), "link": l.Name, "elevated": f.Elevated, "platform": f.Platform},
		})
	})
	return res, err
}

// qaSite finds or makes the organization's Quick Assist site.
func (s *Service) qaSite(ctx context.Context, tx pgx.Tx, org uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM sites WHERE organization_id = $1 AND kind = 'quick_assist'`, org).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name, kind) VALUES ($1, 'Quick Assist', 'quick_assist')
		ON CONFLICT DO NOTHING RETURNING id`, org).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		// A site of that name that is not ours: pick a name that is free.
		err = tx.QueryRow(ctx, `INSERT INTO sites (organization_id, name, kind) VALUES ($1, 'Quick Assist ' || substr(gen_random_uuid()::text, 1, 8), 'quick_assist')
			ON CONFLICT DO NOTHING RETURNING id`, org).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(ctx, `SELECT id FROM sites WHERE organization_id = $1 AND kind = 'quick_assist'`, org).Scan(&id)
		}
	}
	return id, err
}

// RunnerState is a runner's view of its session.
type RunnerState struct {
	State     string `json:"state"`
	EndReason string `json:"endReason,omitempty"`
	// Install is "requested" while the technician asks to keep the agent on
	// this computer; the runner then asks the user (Offer says who offers).
	Install string        `json:"install,omitempty"`
	Offer   *InstallOffer `json:"offer,omitempty"`
}

// InstallOffer names what the user is asked to keep on their computer.
type InstallOffer struct {
	Organization string `json:"organization"`
	Site         string `json:"site"`
}

// Status answers a runner's poll and marks the session seen. A request
// nobody accepted within RequestWait is declined here too, so the runner
// is told without waiting for the sweep.
func (s *Service) Status(ctx context.Context, device uuid.UUID) (*RunnerState, error) {
	var out RunnerState
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var id uuid.UUID
		var requested, expires time.Time
		var org uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id, state, end_reason, requested_at, expires_at, install_state, organization_id FROM quick_assist_sessions WHERE device_id = $1 FOR UPDATE`, device).
			Scan(&id, &out.State, &out.EndReason, &requested, &expires, &out.Install, &org)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		now := s.now()
		switch {
		case out.State == SessionRequested && now.Sub(requested) >= RequestWait:
			out.State, out.EndReason = SessionDeclined, "not_accepted"
		case out.State == SessionActive && !now.Before(expires):
			out.State, out.EndReason = SessionEnded, "max_length"
		default:
			if out.Install == "requested" && out.State == SessionActive {
				out.Offer = &InstallOffer{}
				if err := tx.QueryRow(ctx, `SELECT o.name, s.name FROM organizations o, sites s WHERE o.id = $1 AND s.organization_id = o.id AND s.kind = 'quick_assist'`, org).
					Scan(&out.Offer.Organization, &out.Offer.Site); err != nil {
					return err
				}
			} else {
				out.Install = ""
			}
			if _, err := tx.Exec(ctx, `UPDATE devices SET agent_last_seen_at = $2 WHERE id = $1`, device, now); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET last_seen_at = $2 WHERE id = $1 AND state IN ('requested','active')`, id, now)
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = $2, end_reason = $3, ended_at = $4 WHERE id = $1`, id, out.State, out.EndReason, now)
		return err
	})
	return &out, err
}

// Session is what the console shows of a session. The code is never in it.
type Session struct {
	ID           uuid.UUID  `json:"id"`
	LinkID       uuid.UUID  `json:"linkId"`
	LinkName     string     `json:"linkName"`
	Organization uuid.UUID  `json:"organizationId"`
	DeviceID     *uuid.UUID `json:"deviceId"`
	DeviceName   string     `json:"deviceName"`
	Platform     string     `json:"platform"`
	State        string     `json:"state"`
	Elevated     bool       `json:"elevated"`
	Test         bool       `json:"test"`
	RequestedAt  time.Time  `json:"requestedAt"`
	AcceptedBy   *uuid.UUID `json:"acceptedBy"`
	AcceptedAt   *time.Time `json:"acceptedAt"`
	EndedAt      *time.Time `json:"endedAt"`
	EndReason    string     `json:"endReason"`
	LastSeenAt   time.Time  `json:"lastSeenAt"`
	Cleanup      string     `json:"cleanup"`
	SourceIP     string     `json:"sourceIp"`
	// Disconnected says the runner has not been heard from for a while.
	Disconnected bool `json:"disconnected"`
}

const sessionCols = `s.id, s.link_id, l.name, s.organization_id, s.device_id, coalesce(d.name, ''), coalesce(d.platform, ''), s.state, s.elevated, l.test,
	s.requested_at, s.accepted_by, s.accepted_at, s.ended_at, s.end_reason, s.last_seen_at, s.cleanup, s.source_ip`

const sessionFrom = ` FROM quick_assist_sessions s JOIN quick_assist_links l ON l.id = s.link_id LEFT JOIN devices d ON d.id = s.device_id`

func (s *Service) scanSession(row pgx.Row) (*Session, error) {
	var x Session
	if err := row.Scan(&x.ID, &x.LinkID, &x.LinkName, &x.Organization, &x.DeviceID, &x.DeviceName, &x.Platform, &x.State, &x.Elevated, &x.Test,
		&x.RequestedAt, &x.AcceptedBy, &x.AcceptedAt, &x.EndedAt, &x.EndReason, &x.LastSeenAt, &x.Cleanup, &x.SourceIP); err != nil {
		return nil, err
	}
	x.Disconnected = (x.State == SessionActive || x.State == SessionRequested) && s.now().Sub(x.LastSeenAt) > 3*time.Duration(HeartbeatSeconds)*time.Second
	return &x, nil
}

// ListSessions lists an organization's sessions in the given states.
func (s *Service) ListSessions(ctx context.Context, c access.Caller, org uuid.UUID, states []string) ([]*Session, error) {
	if err := c.Require(rbac.PermQAView, rbac.Org(org)); err != nil {
		return nil, err
	}
	out := []*Session{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+sessionCols+sessionFrom+` WHERE s.organization_id = $1 AND s.state = ANY($2) ORDER BY s.requested_at DESC LIMIT 500`, org, states)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			x, err := s.scanSession(rows)
			if err != nil {
				return err
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	return out, err
}

// Waiting counts the requests waiting for acceptance in the organizations
// the caller may see, for the navigation's badge.
func (s *Service) Waiting(ctx context.Context, c access.Caller) (int, error) {
	n := 0
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT organization_id, count(*) FROM quick_assist_sessions
			WHERE state = 'requested' AND requested_at > $1 GROUP BY organization_id`, s.now().Add(-RequestWait))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var org uuid.UUID
			var k int
			if err := rows.Scan(&org, &k); err != nil {
				return err
			}
			if c.Can(rbac.PermQAView, rbac.Org(org)) {
				n += k
			}
		}
		return rows.Err()
	})
	return n, err
}

func (s *Service) loadSession(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID) (*Session, []byte, error) {
	var hash []byte
	row := tx.QueryRow(ctx, `SELECT `+sessionCols+`, s.session_code_hash`+sessionFrom+` WHERE s.id = $1 FOR UPDATE OF s`, id)
	var x Session
	if err := row.Scan(&x.ID, &x.LinkID, &x.LinkName, &x.Organization, &x.DeviceID, &x.DeviceName, &x.Platform, &x.State, &x.Elevated, &x.Test,
		&x.RequestedAt, &x.AcceptedBy, &x.AcceptedAt, &x.EndedAt, &x.EndReason, &x.LastSeenAt, &x.Cleanup, &x.SourceIP, &hash); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, apperr.NotFound()
		}
		return nil, nil, err
	}
	if !c.Can(rbac.PermQAView, rbac.Org(x.Organization)) {
		return nil, nil, apperr.NotFound()
	}
	return &x, hash, nil
}

func (s *Service) sessionEvent(actor audit.Actor, x *Session, action string, o audit.Outcome, extra map[string]any) audit.Event {
	d := map[string]any{"device": x.DeviceName, "link": x.LinkName}
	for k, v := range extra {
		d[k] = v
	}
	e := audit.Event{Actor: actor, Action: action, OrganizationID: x.Organization, TargetType: "quick_assist_session", TargetID: x.ID.String(), Outcome: o, Details: d}
	if x.DeviceID != nil {
		e.DeviceID = *x.DeviceID
	}
	return e
}

// ErrWrongCode is the answer to a code that does not match; Left is how many
// tries remain.
type ErrWrongCode struct{ Left int }

func (e *ErrWrongCode) Error() string { return "quickassist: that is not the session's code" }

// Accept binds the session to the technician who types the right code.
// Three wrong codes close the request.
func (s *Service) Accept(ctx context.Context, c access.Caller, id uuid.UUID, code string) (*Session, error) {
	var out *Session
	var wrong *ErrWrongCode
	forbidden := false
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		x, hash, err := s.loadSession(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if err := c.Require(rbac.PermQASession, rbac.Org(x.Organization)); err != nil {
			return err
		}
		if !devscope.Allowed(x.Organization) {
			return apperr.Forbidden()
		}
		if x.State != SessionRequested || s.now().Sub(x.RequestedAt) >= RequestWait {
			return apperr.Conflict("not_waiting", "This request is no longer waiting.")
		}
		// While the link mode is own_test only the person who made the
		// link accepts a session from it.
		if x.Test {
			var maker *uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT created_by FROM quick_assist_links WHERE id = $1`, x.LinkID).Scan(&maker); err != nil {
				return err
			}
			if c.Principal == nil || maker == nil || *maker != c.Principal.UserID {
				forbidden = true
				return s.audit.Write(ctx, tx, s.sessionEvent(c.Actor, x, ActionAccept, audit.Denied, map[string]any{"reason": "test_link_other_person"}))
			}
		}
		if !codePattern.MatchString(code) || !compare(codeHash(x.ID, code), hash) {
			var fails int
			if err := tx.QueryRow(ctx, `UPDATE quick_assist_sessions SET code_failures = code_failures + 1 WHERE id = $1 RETURNING code_failures`, x.ID).Scan(&fails); err != nil {
				return err
			}
			wrong = &ErrWrongCode{Left: MaxCodeFailures - fails}
			if fails >= MaxCodeFailures {
				wrong.Left = 0
				if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = 'declined', end_reason = 'code_failed', ended_at = now() WHERE id = $1`, x.ID); err != nil {
					return err
				}
				return s.audit.Write(ctx, tx, s.sessionEvent(c.Actor, x, ActionDecline, audit.Denied, map[string]any{"reason": "code_failed"}))
			}
			return nil
		}
		var by *uuid.UUID
		if c.Principal != nil {
			by = &c.Principal.UserID
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = 'active', accepted_by = $2, accepted_at = now() WHERE id = $1`, x.ID, by); err != nil {
			return err
		}
		x.State, x.AcceptedBy = SessionActive, by
		out = x
		return s.audit.Write(ctx, tx, s.sessionEvent(c.Actor, x, ActionAccept, audit.Success, nil))
	})
	if err != nil {
		return nil, err
	}
	if forbidden {
		return nil, apperr.Forbidden()
	}
	if wrong != nil {
		return nil, wrong
	}
	return out, nil
}

// Decline refuses a waiting request.
func (s *Service) Decline(ctx context.Context, c access.Caller, id uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		x, _, err := s.loadSession(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if err := c.Require(rbac.PermQASession, rbac.Org(x.Organization)); err != nil {
			return err
		}
		if x.State != SessionRequested {
			return apperr.Conflict("not_waiting", "This request is no longer waiting.")
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = 'declined', end_reason = 'declined', ended_at = now() WHERE id = $1`, x.ID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.sessionEvent(c.Actor, x, ActionDecline, audit.Success, map[string]any{"reason": "declined"}))
	})
}

// holder is the holder rule: the person who accepted, or someone who may
// take sessions over.
func holder(c access.Caller, x *Session) bool {
	if c.Principal != nil && x.AcceptedBy != nil && *x.AcceptedBy == c.Principal.UserID {
		return true
	}
	return c.Can(rbac.PermQATakeover, rbac.Org(x.Organization))
}

// End ends an active session. The runner then cleans up and reports.
func (s *Service) End(ctx context.Context, c access.Caller, id uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		x, _, err := s.loadSession(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if err := c.Require(rbac.PermQASession, rbac.Org(x.Organization)); err != nil {
			return err
		}
		if x.State != SessionActive && x.State != SessionRequested {
			return apperr.Conflict("not_active", "This session has ended.")
		}
		if !holder(c, x) {
			return apperr.Forbidden()
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = 'ended', end_reason = 'technician', ended_at = now() WHERE id = $1`, x.ID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.sessionEvent(c.Actor, x, ActionEnd, audit.Success, map[string]any{"reason": "technician"}))
	})
}

// Takeover hands an active session to the caller, who needs the takeover
// permission.
func (s *Service) Takeover(ctx context.Context, c access.Caller, id uuid.UUID) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		x, _, err := s.loadSession(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if err := c.Require(rbac.PermQATakeover, rbac.Org(x.Organization)); err != nil {
			return err
		}
		if x.State != SessionActive || c.Principal == nil {
			return apperr.Conflict("not_active", "Only an active session can be taken over.")
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET accepted_by = $2 WHERE id = $1`, x.ID, c.Principal.UserID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.sessionEvent(c.Actor, x, ActionTakeover, audit.Success, map[string]any{"from": x.AcceptedBy}))
	})
}

// Cleanup is a runner's signed report of what it removed.
type Cleanup struct {
	Result string `json:"result"` // verified or residue
	Checks []struct {
		Name   string `json:"name"`
		OK     bool   `json:"ok"`
		Detail string `json:"detail,omitempty"`
	} `json:"checks"`
	ManifestSHA256 string `json:"manifestSha256"`
}

// RunnerEnd records the runner's end of its session and its cleanup report,
// and revokes the session's key: the session's key is valid until the
// session ends.
func (s *Service) RunnerEnd(ctx context.Context, device uuid.UUID, ip netip.Addr, reason string, rep *Cleanup) error {
	reason = clean(reason, 40)
	if reason == "" {
		reason = "runner"
	}
	result := "unconfirmed"
	var raw []byte
	if rep != nil {
		if rep.Result != "verified" && rep.Result != "residue" {
			return apperr.Invalid("result", "Use verified or residue.")
		}
		result = rep.Result
		var err error
		if raw, err = json.Marshal(rep); err != nil || len(raw) > maxReport {
			return apperr.Invalid("checks", "The report is too large.")
		}
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var id uuid.UUID
		var state string
		if err := tx.QueryRow(ctx, `SELECT id, state FROM quick_assist_sessions WHERE device_id = $1 FOR UPDATE`, device).Scan(&id, &state); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		if state == SessionConverted {
			// The permanent agent answered: the session moves to its device
			// and the temporary one goes, with its key, after this report.
			var newDev uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT converted_device_id FROM quick_assist_sessions WHERE id = $1`, id).Scan(&newDev); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET device_id = $2, cleanup = $3, cleanup_report = $4, ended_at = coalesce(ended_at, now()) WHERE id = $1`, id, newDev, result, raw); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM devices WHERE id = $1 AND quick_assist`, device); err != nil {
				return err
			}
			var org uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT organization_id FROM quick_assist_sessions WHERE id = $1`, id).Scan(&org); err != nil {
				return err
			}
			return s.audit.Write(ctx, tx, audit.Event{
				Actor:  audit.Actor{Type: audit.ActorAgent, ID: device, Label: "quick assist runner", SourceIP: ip},
				Action: ActionCleanup, OrganizationID: org, DeviceID: newDev, TargetType: "quick_assist_session", TargetID: id.String(),
				Outcome: audit.Success, Details: map[string]any{"result": result, "reason": "converted"},
			})
		}
		if state == SessionRequested || state == SessionActive {
			state = SessionEnded
			if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = 'ended', end_reason = $2, ended_at = now() WHERE id = $1`, id, reason); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET cleanup = $2, cleanup_report = $3 WHERE id = $1`, id, result, raw); err != nil {
			return err
		}
		// The key stops working: nothing signed by it is accepted again.
		if _, err := tx.Exec(ctx, `UPDATE devices SET agent_public_key = NULL, enrolled_at = NULL WHERE id = $1`, device); err != nil {
			return err
		}
		var org uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT organization_id FROM quick_assist_sessions WHERE id = $1`, id).Scan(&org); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor:  audit.Actor{Type: audit.ActorAgent, ID: device, Label: "quick assist runner", SourceIP: ip},
			Action: ActionCleanup, OrganizationID: org, DeviceID: device, TargetType: "quick_assist_session", TargetID: id.String(),
			Outcome: audit.Success, Details: map[string]any{"result": result, "reason": reason},
		})
	})
}

// Sweep does the server's periodic work: it declines requests nobody
// accepted, marks sessions whose runner went quiet as lost, ends those past
// their length, closes cleanups never reported as unconfirmed, and deletes
// what is past retention. Each organization is checked with devscope first.
func (s *Service) Sweep(ctx context.Context) error {
	now := s.now()
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		type row struct {
			id, org uuid.UUID
			device  *uuid.UUID
		}
		do := func(query string, args []any, state, reason string, action string) error {
			rows, err := tx.Query(ctx, query, args...)
			if err != nil {
				return err
			}
			var hit []row
			for rows.Next() {
				var r row
				if err := rows.Scan(&r.id, &r.org, &r.device); err != nil {
					rows.Close()
					return err
				}
				if devscope.Allowed(r.org) {
					hit = append(hit, r)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, r := range hit {
				if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = $2, end_reason = $3, ended_at = $4,
						cleanup = CASE WHEN $2 = 'lost' THEN 'unconfirmed' ELSE cleanup END WHERE id = $1`, r.id, state, reason, now); err != nil {
					return err
				}
				e := audit.Event{Actor: audit.SystemActor("quickassist"), Action: action, OrganizationID: r.org,
					TargetType: "quick_assist_session", TargetID: r.id.String(), Outcome: audit.Success, Details: map[string]any{"reason": reason}}
				if r.device != nil {
					e.DeviceID = *r.device
				}
				if err := s.audit.Write(ctx, tx, e); err != nil {
					return err
				}
			}
			return nil
		}
		if err := do(`SELECT id, organization_id, device_id FROM quick_assist_sessions WHERE state = 'requested' AND requested_at < $1 FOR UPDATE`,
			[]any{now.Add(-RequestWait)}, SessionDeclined, "not_accepted", ActionDecline); err != nil {
			return err
		}
		if err := do(`SELECT id, organization_id, device_id FROM quick_assist_sessions WHERE state = 'active' AND expires_at < $1 FOR UPDATE`,
			[]any{now}, SessionEnded, "max_length", ActionEnd); err != nil {
			return err
		}
		if err := do(`SELECT id, organization_id, device_id FROM quick_assist_sessions WHERE state IN ('requested','active') AND last_seen_at < $1 FOR UPDATE`,
			[]any{now.Add(-LostAfter)}, SessionLost, "lost", ActionLost); err != nil {
			return err
		}
		// Ended sessions whose runner never reported: unconfirmed, and the
		// key stops working.
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET cleanup = 'unconfirmed'
			WHERE state IN ('ended','declined') AND cleanup = 'none' AND ended_at < $1 AND organization_id = ANY($2)`,
			now.Add(-CleanupWait), s.allowedOrgs(ctx, tx)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE devices SET agent_public_key = NULL, enrolled_at = NULL
			WHERE quick_assist AND agent_public_key IS NOT NULL AND id IN (SELECT device_id FROM quick_assist_sessions WHERE state IN ('ended','declined','lost') AND cleanup <> 'none')`); err != nil {
			return err
		}
		// Retention.
		old := now.Add(-Retention)
		if _, err := tx.Exec(ctx, `DELETE FROM devices WHERE quick_assist AND id IN (SELECT device_id FROM quick_assist_sessions WHERE ended_at < $1 AND state <> 'converted' AND organization_id = ANY($2))`,
			old, s.allowedOrgs(ctx, tx)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM quick_assist_sessions WHERE ended_at < $1 AND organization_id = ANY($2)`, old, s.allowedOrgs(ctx, tx))
		return err
	})
}

// allowedOrgs lists the organizations the dev scope lets automatic work
// reach.
func (s *Service) allowedOrgs(ctx context.Context, tx pgx.Tx) []uuid.UUID {
	rows, err := tx.Query(ctx, `SELECT id FROM organizations`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if rows.Scan(&id) == nil && devscope.Allowed(id) {
			out = append(out, id)
		}
	}
	return out
}

// Run sweeps once a minute until the context ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = s.Sweep(ctx)
		}
	}
}

// NewCode returns a six-digit session code (for runners and tests).
func NewCode() string {
	b := make([]byte, 4)
	for {
		_, _ = rand.Read(b)
		n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		if n < 4_000_000_000 { // avoid modulo bias
			return pad6(n % 1_000_000)
		}
	}
}

func pad6(n uint32) string {
	s := itoa(int(n))
	return strings.Repeat("0", 6-len(s)) + s
}
