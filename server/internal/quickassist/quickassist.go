// Package quickassist is Quick Assist, ad-hoc support sessions (ADR-0080):
// signed links a technician gives a user, the session a download starts, the
// code the technician types to accept it, and the end of a session.
//
// Until code signing exists the whole feature runs in the restricted mode
// (decided in review, pending the owner): the setting quickassist.link_mode
// is "own_test" unless it is set to "open", and in that mode only one-time
// links can be made, they are marked as test links, and only the person who
// made one can accept a session from it. Lifting the restriction is that one
// setting.
package quickassist

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

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

// Token prefixes (ADR-0080).
const (
	PrefixOneTime   = "qal_"
	PrefixPermanent = "qap_" //nolint:gosec // a token prefix, not a credential
)

// Link kinds and states.
const (
	KindOneTime   = "one_time"
	KindPermanent = "permanent"

	LinkActive  = "active"
	LinkUsed    = "used"
	LinkExpired = "expired"
	LinkRevoked = "revoked"
)

// Link modes: the one setting that restricts links until signing exists.
const (
	SettingLinkMode = "quickassist.link_mode"
	ModeOwnTest     = "own_test"
	ModeOpen        = "open"
)

// Limits (ADR-0080). The bucket and the caps are settings in the ADR; the
// defaults are what is built so far.
const (
	DefaultOneTimeLife = 24 * time.Hour
	MaxOneTimeLife     = 7 * 24 * time.Hour
	MaxPermanentLinks  = 5
	bucketBurst        = 5.0
	bucketRefill       = 3 * time.Minute
	maxName            = 100
	maxNote            = 1000
)

// Audit actions (ADR-0007, ADR-0080 Security).
const (
	ActionLinkCreate    = "quickassist.link.create"
	ActionLinkRevoke    = "quickassist.link.revoke"
	ActionLinkPause     = "quickassist.link.pause"
	ActionLinkDownload  = "quickassist.link.download"
	ActionLinkThrottled = "quickassist.link.throttled"
	ActionLinkDenied    = "quickassist.link.denied"
	ActionRequest       = "quickassist.session.request"
	ActionAccept        = "quickassist.session.accept"
	ActionDecline       = "quickassist.session.decline"
	ActionTakeover      = "quickassist.session.takeover"
	ActionEnd           = "quickassist.session.end"
	ActionLost          = "quickassist.session.lost"
	ActionCleanup       = "quickassist.session.cleanup"
)

// Errors the public side answers with one message, so no answer tells a
// token that never existed from one that expired.
var (
	ErrLinkUnavailable = errors.New("quickassist: the link is not available")
	ErrThrottled       = errors.New("quickassist: the link is busy")
	ErrRateLimited     = errors.New("quickassist: too many requests")
)

// Service is Quick Assist.
type Service struct {
	db        *database.DB
	audit     *audit.Logger
	key       ed25519.PrivateKey
	publicURL string
	now       func() time.Time
	// perAddr limits downloads and enrollments from one address; the
	// per-link bucket is the primary limit and lives in the database.
	downloads, enrolls, pages *auth.KeyedLimiter
	// onThrottled, when set, hears of a link that went over its bucket, at
	// most once per link per day.
	removeNode  NodeRemover
	onThrottled func(ctx context.Context, org uuid.UUID, link string)
}

// OnThrottled sets what is told that a link went over its bucket (the
// alert mail). It runs after the transaction commits.
func (s *Service) OnThrottled(f func(ctx context.Context, org uuid.UUID, link string)) {
	s.onThrottled = f
}

// New builds the service. publicURL is the console's address the ticket
// names; key signs tickets (the server's job key).
func New(db *database.DB, log *audit.Logger, key ed25519.PrivateKey, publicURL string) *Service {
	return &Service{
		db: db, audit: log, key: key, publicURL: publicURL, now: time.Now,
		downloads: auth.NewKeyedLimiter(12*time.Minute, 5, 10_000),
		enrolls:   auth.NewKeyedLimiter(3*time.Minute, 20, 10_000),
		pages:     auth.NewKeyedLimiter(time.Second, 60, 10_000),
	}
}

// PublicKey is the key a runner verifies tickets with.
func (s *Service) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

func hashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

func newToken(prefix string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// Mode reads the link mode: own_test unless the setting says open.
func (s *Service) Mode(ctx context.Context) (string, error) {
	var raw []byte
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, SettingLinkMode).Scan(&raw)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ModeOwnTest, nil
	}
	if err != nil {
		return "", err
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil || v != ModeOpen {
		return ModeOwnTest, nil //nolint:nilerr // a setting that cannot be read is the restricted mode
	}
	return ModeOpen, nil
}

// SetMode changes the link mode. It needs the platform-wide settings
// permission and is audited.
func (s *Service) SetMode(ctx context.Context, c access.Caller, mode string) error {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return err
	}
	if mode != ModeOwnTest && mode != ModeOpen {
		return apperr.Invalid("mode", "Use own_test or open.")
	}
	raw, _ := json.Marshal(mode)
	var by *uuid.UUID
	if c.Principal != nil {
		by = &c.Principal.UserID
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO settings (key, value, updated_by) VALUES ($1, $2, $3)
			ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now(), updated_by = EXCLUDED.updated_by`,
			SettingLinkMode, raw, by); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "quickassist.settings.update", Outcome: audit.Success,
			TargetType: "setting", TargetID: SettingLinkMode, Details: map[string]any{"mode": mode}})
	})
}

// Link is what the console shows of a link: never the token.
type Link struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	SiteID         *uuid.UUID `json:"siteId"`
	Kind           string     `json:"kind"`
	Name           string     `json:"name"`
	Note           string     `json:"note"`
	State          string     `json:"state"`
	Paused         bool       `json:"paused"`
	Test           bool       `json:"test"`
	ExpiresAt      *time.Time `json:"expiresAt"`
	CreatedBy      *uuid.UUID `json:"createdBy"`
	CreatedAt      time.Time  `json:"createdAt"`
	UsedAt         *time.Time `json:"usedAt"`
	LastUsedAt     *time.Time `json:"lastUsedAt"`
	DownloadCount  int        `json:"downloadCount"`
}

const linkCols = `id, organization_id, site_id, kind, name, note, state, paused, test, expires_at, created_by, created_at, used_at, last_used_at, download_count`

func scanLink(row pgx.Row, now time.Time) (*Link, error) {
	var l Link
	if err := row.Scan(&l.ID, &l.OrganizationID, &l.SiteID, &l.Kind, &l.Name, &l.Note, &l.State, &l.Paused, &l.Test,
		&l.ExpiresAt, &l.CreatedBy, &l.CreatedAt, &l.UsedAt, &l.LastUsedAt, &l.DownloadCount); err != nil {
		return nil, err
	}
	if l.State == LinkActive && l.ExpiresAt != nil && !now.Before(*l.ExpiresAt) {
		l.State = LinkExpired
	}
	return &l, nil
}

// CreateInput makes a link.
type CreateInput struct {
	OrganizationID uuid.UUID
	SiteID         *uuid.UUID
	Kind           string
	Name, Note     string
	// Life is a one-time link's lifetime; zero is 24 hours.
	Life time.Duration
}

// NewLink is a created link and its token, shown once.
type NewLink struct {
	Link  *Link  `json:"link"`
	Token string `json:"token"`
	Path  string `json:"path"`
}

// CreateLink makes a link. A permanent link needs quickassist.link.permanent
// and the API has checked step-up; while the link mode is own_test only
// one-time test links can be made.
func (s *Service) CreateLink(ctx context.Context, c access.Caller, in CreateInput) (*NewLink, error) {
	if in.Kind != KindOneTime && in.Kind != KindPermanent {
		return nil, apperr.Invalid("kind", "Use one_time or permanent.")
	}
	if len(in.Name) > maxName || len(in.Note) > maxNote {
		return nil, apperr.Invalid("name", "The name or note is too long.")
	}
	perm := rbac.PermQALinkCreate
	if in.Kind == KindPermanent {
		perm = rbac.PermQALinkPermanent
	}
	org := rbac.Org(in.OrganizationID)
	if err := c.Require(perm, org); err != nil {
		return nil, err
	}
	if !devscope.Allowed(in.OrganizationID) {
		return nil, apperr.Forbidden()
	}
	mode, err := s.Mode(ctx)
	if err != nil {
		return nil, err
	}
	if mode == ModeOwnTest && in.Kind == KindPermanent {
		return nil, apperr.Conflict("test_links_only", "Until code signing exists only one-time test links can be made.")
	}
	var expires *time.Time
	if in.Kind == KindOneTime {
		life := in.Life
		if life == 0 {
			life = DefaultOneTimeLife
		}
		if life < time.Minute || life > MaxOneTimeLife {
			return nil, apperr.Invalid("life", "A one-time link lasts 1 minute to 7 days.")
		}
		t := s.now().Add(life)
		expires = &t
	}
	prefix := PrefixOneTime
	if in.Kind == KindPermanent {
		prefix = PrefixPermanent
	}
	tok, err := newToken(prefix)
	if err != nil {
		return nil, err
	}
	var out *Link
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM organizations WHERE id = $1`, in.OrganizationID).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.NotFound()
			}
			return err
		}
		if in.SiteID != nil {
			if err := tx.QueryRow(ctx, `SELECT 1 FROM sites WHERE id = $1 AND organization_id = $2 AND kind = 'normal'`, *in.SiteID, in.OrganizationID).Scan(&one); err != nil {
				return apperr.Invalid("siteId", "Choose a site of this organization.")
			}
		}
		if in.Kind == KindPermanent {
			var live int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM quick_assist_links WHERE organization_id = $1 AND kind = 'permanent' AND state = 'active'`, in.OrganizationID).Scan(&live); err != nil {
				return err
			}
			if live >= MaxPermanentLinks {
				return apperr.Conflict("too_many_links", fmt.Sprintf("An organization may have %d live permanent links.", MaxPermanentLinks))
			}
		}
		var by *uuid.UUID
		if c.Principal != nil {
			by = &c.Principal.UserID
		}
		row := tx.QueryRow(ctx, `INSERT INTO quick_assist_links (organization_id, site_id, kind, name, note, token_hash, expires_at, created_by, test, created_at, bucket_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10) RETURNING `+linkCols,
			in.OrganizationID, in.SiteID, in.Kind, in.Name, in.Note, hashToken(tok), expires, by, mode == ModeOwnTest, s.now())
		if out, err = scanLink(row, s.now()); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.linkEvent(c.Actor, out, ActionLinkCreate, audit.Success, nil))
	})
	if err != nil {
		return nil, err
	}
	return &NewLink{Link: out, Token: tok, Path: "/qa/" + tok}, nil
}

func (s *Service) linkEvent(actor audit.Actor, l *Link, action string, o audit.Outcome, extra map[string]any) audit.Event {
	d := map[string]any{"kind": l.Kind, "name": l.Name, "test": l.Test}
	for k, v := range extra {
		d[k] = v
	}
	return audit.Event{Actor: actor, Action: action, OrganizationID: l.OrganizationID, TargetType: "quick_assist_link",
		TargetID: l.ID.String(), Outcome: o, Details: d}
}

// ListLinks lists the organization's links the caller may see.
func (s *Service) ListLinks(ctx context.Context, c access.Caller, org uuid.UUID) ([]*Link, error) {
	if err := c.Require(rbac.PermQAView, rbac.Org(org)); err != nil {
		return nil, err
	}
	out := []*Link{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+linkCols+` FROM quick_assist_links WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 500`, org)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			l, err := scanLink(rows, s.now())
			if err != nil {
				return err
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Service) loadLink(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID) (*Link, error) {
	l, err := scanLink(tx.QueryRow(ctx, `SELECT `+linkCols+` FROM quick_assist_links WHERE id = $1 FOR UPDATE`, id), s.now())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermQAView, rbac.Org(l.OrganizationID)) {
		return nil, apperr.NotFound()
	}
	return l, nil
}

// RevokeLink ends a link at once. A waiting request from it is declined; a
// running session continues (End session is the kill switch). Revoking
// somebody else's link needs step-up, which the API checks when ByOther is
// the answer.
func (s *Service) RevokeLink(ctx context.Context, c access.Caller, id uuid.UUID, stepUp func() error) (*Link, error) {
	var out *Link
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		l, err := s.loadLink(ctx, tx, c, id)
		if err != nil {
			return err
		}
		perm := rbac.PermQALinkCreate
		if l.Kind == KindPermanent {
			perm = rbac.PermQALinkPermanent
		}
		if err := c.Require(perm, rbac.Org(l.OrganizationID)); err != nil {
			return err
		}
		if c.Principal != nil && (l.CreatedBy == nil || *l.CreatedBy != c.Principal.UserID) && stepUp != nil {
			if err := stepUp(); err != nil {
				return err
			}
		}
		if l.State == LinkRevoked {
			out = l
			return nil
		}
		var by *uuid.UUID
		if c.Principal != nil {
			by = &c.Principal.UserID
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_links SET state = 'revoked', revoked_at = now(), revoked_by = $2 WHERE id = $1`, id, by); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_sessions SET state = 'declined', end_reason = 'link_revoked', ended_at = now()
			WHERE link_id = $1 AND state = 'requested'`, id); err != nil {
			return err
		}
		l.State = LinkRevoked
		out = l
		return s.audit.Write(ctx, tx, s.linkEvent(c.Actor, l, ActionLinkRevoke, audit.Success, nil))
	})
	return out, err
}

// PauseLink pauses or resumes a permanent link, without step-up, so a
// technician can stop a flood in one click.
func (s *Service) PauseLink(ctx context.Context, c access.Caller, id uuid.UUID, paused bool) (*Link, error) {
	var out *Link
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		l, err := s.loadLink(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if err := c.Require(rbac.PermQALinkPermanent, rbac.Org(l.OrganizationID)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE quick_assist_links SET paused = $2 WHERE id = $1`, id, paused); err != nil {
			return err
		}
		l.Paused = paused
		out = l
		return s.audit.Write(ctx, tx, s.linkEvent(c.Actor, l, ActionLinkPause, audit.Success, map[string]any{"paused": paused}))
	})
	return out, err
}

// Page is what the public link page shows.
type Page struct {
	Organization string `json:"organization"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Test         bool   `json:"test"`
	Server       string `json:"server"`
}

type linkRow struct {
	Link
	orgName string
	tokens  float64
	bucket  time.Time
}

// lookup finds the link a token names, always hashing and always reading,
// so the time does not depend on the token's state. It returns
// ErrLinkUnavailable for every reason a link cannot be used.
func (s *Service) lookup(ctx context.Context, tx pgx.Tx, token string, lock bool) (*linkRow, error) {
	valid := (len(token) > 4 && len(token) < 100) && (token[:4] == PrefixOneTime || token[:4] == PrefixPermanent)
	h := hashToken(token)
	q := `SELECT l.id, l.organization_id, l.site_id, l.kind, l.name, l.note, l.state, l.paused, l.test, l.expires_at, l.created_by,
			l.created_at, l.used_at, l.last_used_at, l.download_count, o.name, l.bucket_tokens, l.bucket_at
		FROM quick_assist_links l JOIN organizations o ON o.id = l.organization_id WHERE l.token_hash = $1`
	if lock {
		q += ` FOR UPDATE OF l`
	}
	var r linkRow
	err := tx.QueryRow(ctx, q, h).Scan(&r.ID, &r.OrganizationID, &r.SiteID, &r.Kind, &r.Name, &r.Note, &r.State, &r.Paused, &r.Test, &r.ExpiresAt,
		&r.CreatedBy, &r.CreatedAt, &r.UsedAt, &r.LastUsedAt, &r.DownloadCount, &r.orgName, &r.tokens, &r.bucket)
	if errors.Is(err, pgx.ErrNoRows) || !valid {
		return nil, ErrLinkUnavailable
	}
	if err != nil {
		return nil, err
	}
	if r.State != LinkActive || r.Paused || (r.ExpiresAt != nil && !s.now().Before(*r.ExpiresAt)) || !devscope.Allowed(r.OrganizationID) {
		return nil, ErrLinkUnavailable
	}
	return &r, nil
}

// Resolve answers the public page for a token without using the link.
func (s *Service) Resolve(ctx context.Context, ip netip.Addr, token string) (*Page, error) {
	if !s.pages.Allow(auth.LimitKey(ip)) {
		return nil, ErrRateLimited
	}
	var p *Page
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		r, err := s.lookup(ctx, tx, token, false)
		if err != nil {
			return err
		}
		p = &Page{Organization: r.orgName, Name: r.Name, Kind: r.Kind, Test: r.Test, Server: s.publicURL}
		return nil
	})
	return p, err
}

// Download uses a link to start a download: a one-time link becomes used;
// a permanent link spends a token from its bucket. It returns the trailer to
// append to the runner and the link. A link over its bucket is audited as
// throttled and answers ErrThrottled.
func (s *Service) Download(ctx context.Context, ip netip.Addr, token string) (trailer []byte, link *Link, err error) {
	if !s.downloads.Allow(auth.LimitKey(ip)) {
		return nil, nil, ErrRateLimited
	}
	throttled := false
	var alertOrg uuid.UUID
	var alertLink string
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		r, err := s.lookup(ctx, tx, token, true)
		if err != nil {
			return err
		}
		now := s.now()
		if r.Kind == KindOneTime {
			if _, err := tx.Exec(ctx, `UPDATE quick_assist_links SET state = 'used', used_at = $2, last_used_at = $2, download_count = download_count + 1 WHERE id = $1`, r.ID, now); err != nil {
				return err
			}
		} else {
			tokens := min(bucketBurst, r.tokens+now.Sub(r.bucket).Seconds()/bucketRefill.Seconds())
			if tokens < 1 {
				if _, err := tx.Exec(ctx, `UPDATE quick_assist_links SET bucket_tokens = $2, bucket_at = $3 WHERE id = $1`, r.ID, tokens, now); err != nil {
					return err
				}
				if err := s.audit.Write(ctx, tx, s.linkEvent(audit.Actor{Type: audit.ActorSystem, Label: "quickassist", SourceIP: ip}, &r.Link, ActionLinkThrottled, audit.Denied, nil)); err != nil {
					return err
				}
				throttled = true
				var fresh bool
				if err := tx.QueryRow(ctx, `UPDATE quick_assist_links SET last_alert_at = $2::timestamptz WHERE id = $1
					AND (last_alert_at IS NULL OR last_alert_at < $2::timestamptz - interval '1 day') RETURNING true`, r.ID, now).Scan(&fresh); err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				if fresh {
					alertOrg, alertLink = r.OrganizationID, r.Name
					if alertLink == "" {
						alertLink = "an unnamed link"
					}
				}
				return nil
			}
			if _, err := tx.Exec(ctx, `UPDATE quick_assist_links SET bucket_tokens = $2, bucket_at = $3, last_used_at = $3, download_count = download_count + 1 WHERE id = $1`, r.ID, tokens-1, now); err != nil {
				return err
			}
		}
		t, err := qaticketSign(s.key, r.ID, s.publicURL, now.Add(ticketLife))
		if err != nil {
			return err
		}
		trailer, link = t, &r.Link
		return s.audit.Write(ctx, tx, s.linkEvent(audit.Actor{Type: audit.ActorSystem, Label: "quickassist user", SourceIP: ip}, &r.Link, ActionLinkDownload, audit.Success, nil))
	})
	if err == nil && throttled {
		if alertOrg != uuid.Nil && s.onThrottled != nil && devscope.Allowed(alertOrg) {
			s.onThrottled(ctx, alertOrg, alertLink)
		}
		return nil, nil, ErrThrottled
	}
	return trailer, link, err
}

func compare(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

func itoa(n int) string { return strconv.Itoa(n) }

// ticketLife is how long a downloaded runner's ticket is good for.
const ticketLife = qaticket.Lifetime

func qaticketSign(key ed25519.PrivateKey, link uuid.UUID, server string, expiry time.Time) ([]byte, error) {
	return qaticket.Sign(key, qaticket.Ticket{Link: link.String(), Server: server, Expiry: expiry.Unix()})
}
