package remote

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Kind is a type of remote session.
type Kind string

// Session kinds.
const (
	KindDesktop  Kind = "desktop"
	KindTerminal Kind = "terminal"
	KindFiles    Kind = "files"
	// KindRDP is a desktop over Windows Remote Desktop (ADR-0026):
	// MeshCentral's web RDP client, tunneled to the device's RDP port by
	// the agent. It needs the remote desktop permission.
	KindRDP Kind = "rdp"
)

// permission is what each kind requires at the device's site.
func (k Kind) permission() (rbac.Permission, bool) {
	switch k {
	case KindDesktop, KindRDP:
		return rbac.PermRemoteDesktop, true
	case KindTerminal:
		return rbac.PermTerminal, true
	case KindFiles:
		return rbac.PermFiles, true
	}
	return "", false
}

// viewMode is MeshCentral's device page tab for each kind.
func (k Kind) viewMode() string {
	switch k {
	case KindTerminal:
		return "12"
	case KindFiles:
		return "13"
	}
	return "11"
}

// LaunchPath is the gateway path that redeems a launch token on the
// MeshCentral hostname. MeshCentral has no route under /.easyrmm/.
const LaunchPath = "/.easyrmm/launch"

// LaunchTTL is how long a launch link can be opened.
const LaunchTTL = time.Minute

// hideFlags hides MeshCentral's header, tabs, footer, title, side bar and
// back buttons, leaving only the session view.
const hideFlags = "63"

// Launch is an authorized remote session, ready to embed.
type Launch struct {
	GrantID   uuid.UUID `json:"grantId"`
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expiresAt"`
	Kind      Kind      `json:"kind"`
	DeviceID  uuid.UUID `json:"deviceId"`
	// InternalCA is set when the session's origin uses the server's own
	// certificate authority (ADR-0016), which the browser must trust for
	// that origin before the session can load.
	InternalCA bool `json:"internalCa,omitempty"`
}

var (
	errNoAgent = apperr.Conflict("remote_agent_missing", "This device has no remote-access agent.")
	errOffline = apperr.Conflict("device_offline", "The device is offline. Remote sessions need the device to be online.")
	// ErrUnavailable is returned while MeshCentral cannot be reached.
	ErrUnavailable = apperr.Unavailable("remote_unavailable", "Remote access is unavailable right now. Try again in a minute; if it persists, ask an administrator to check the MeshCentral service.")
)

// StartSession authorizes a remote session of the given kind on a device
// for the caller's EasyRMM session, makes sure the caller's MeshCentral
// account has exactly the rights EasyRMM grants at that site, records the
// launch in the audit log and returns a one-time link for the iframe.
func (s *Service) StartSession(ctx context.Context, c access.Caller, sessionID, deviceID uuid.UUID, kind Kind) (*Launch, error) {
	perm, ok := kind.permission()
	if !ok {
		return nil, apperr.Invalid("kind", "Choose desktop, RDP, terminal or files.")
	}
	d, err := devices.Lookup(ctx, s.db, c, deviceID)
	if err != nil {
		return nil, err
	}
	res := rbac.Site(d.OrganizationID, d.SiteID)
	if err := c.Require(perm, res); err != nil {
		_ = s.audit.Record(ctx, audit.Event{
			Actor: c.Actor, Action: "device.remote_session", OrganizationID: d.OrganizationID, SiteID: d.SiteID,
			DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(), Outcome: audit.Denied,
			Details: map[string]any{"kind": string(kind), "device": d.Name},
		})
		return nil, err
	}
	if d.MeshNodeID == "" {
		return nil, errNoAgent
	}
	if !d.RemoteOnline {
		return nil, errOffline
	}
	if !s.mesh.Connected() {
		return nil, ErrUnavailable
	}
	if err := s.ensureAccess(ctx, c, d); err != nil {
		return nil, err
	}

	token, hash, err := newSecret()
	if err != nil {
		return nil, err
	}
	now := s.now()
	l := &Launch{Kind: kind, DeviceID: d.ID, ExpiresAt: now.Add(LaunchTTL)}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var ip *string
		if c.Actor.SourceIP.IsValid() {
			v := c.Actor.SourceIP.String()
			ip = &v
		}
		if err := tx.QueryRow(ctx, `INSERT INTO remote_grants
			(launch_hash, session_id, user_id, device_id, organization_id, site_id, kind, launch_expires_at, source_ip)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::inet) RETURNING id`,
			hash, sessionID, c.Principal.UserID, d.ID, d.OrganizationID, d.SiteID, string(kind), l.ExpiresAt, ip).
			Scan(&l.GrantID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "device.remote_session", OrganizationID: d.OrganizationID, SiteID: d.SiteID,
			DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(), Outcome: audit.Success,
			Details: map[string]any{"kind": string(kind), "device": d.Name, "grant_id": l.GrantID.String()},
		})
	})
	if err != nil {
		return nil, fmt.Errorf("remote: recording session grant: %w", err)
	}
	u := *s.cfg.MeshURL
	u.Path = LaunchPath
	u.RawQuery = url.Values{"t": {token}}.Encode()
	l.URL = u.String()
	return l, nil
}

// ensureAccess makes sure the caller's MeshCentral account exists and holds
// the rights EasyRMM grants at the device's site, without waiting for the
// next reconciliation.
func (s *Service) ensureAccess(ctx context.Context, c access.Caller, d *devices.Device) error {
	meshID, err := s.meshOf(ctx, d.SiteID)
	if err != nil {
		return err
	}
	if meshID == "" {
		// The site is new and its group not created yet.
		if err := s.Reconcile(ctx); err != nil {
			s.log.Warn("remote access: reconciliation before a session launch failed", "error", err)
		}
		if meshID, err = s.meshOf(ctx, d.SiteID); err != nil {
			return err
		}
		if meshID == "" {
			return ErrUnavailable
		}
	}
	a := accessFor(c.Principal, d.OrganizationID, d.SiteID)
	name, err := s.displayName(ctx, c.Principal.UserID)
	if err != nil {
		return err
	}
	err = s.mesh.AddUser(ctx, accountName(c.Principal.UserID), truncateRunes(name, 256), meshcentral.TechnicianSiteRights)
	if err != nil && !meshcentral.IsAlreadyExists(err) {
		return s.unavailable("creating MeshCentral account", err)
	}
	if err := s.mesh.SetMeshRights(ctx, meshID, accountID(c.Principal.UserID), a.Rights()); err != nil {
		return s.unavailable("granting MeshCentral rights", err)
	}
	return nil
}

func (s *Service) unavailable(what string, err error) error {
	s.log.Error("remote access: "+what+" failed", "error", err)
	return ErrUnavailable
}

func (s *Service) meshOf(ctx context.Context, siteID uuid.UUID) (string, error) {
	var id string
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT mesh_id FROM mesh_sites WHERE site_id = $1`, siteID).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return id, err
}

func (s *Service) displayName(ctx context.Context, userID uuid.UUID) (string, error) {
	var name string
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT display_name FROM users WHERE id = $1`, userID).Scan(&name)
	})
	return name, err
}

// ErrGrantInvalid means a launch link or gateway cookie is unknown, used,
// expired, or belongs to a session that has ended.
var ErrGrantInvalid = errors.New("remote: grant is not valid")

// Redemption is the result of opening a launch link.
type Redemption struct {
	SessionID uuid.UUID
	Cookie    string // the gateway cookie value
	Target    string // MeshCentral path and query to continue to
}

// Redeem exchanges a launch token for a gateway cookie and the MeshCentral
// address that signs the browser in and opens the device. Each token works
// once, within LaunchTTL, and only while its EasyRMM session is valid.
func (s *Service) Redeem(ctx context.Context, token string) (*Redemption, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrGrantInvalid
	}
	hash := hashSecret(token)
	cookie, cookieHash, err := newSecret()
	if err != nil {
		return nil, err
	}
	now := s.now()
	var out *Redemption
	var userID uuid.UUID
	var nodeID, kind string
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var grantID uuid.UUID
		var sessionID uuid.UUID
		var expires time.Time
		var redeemed *time.Time
		err := tx.QueryRow(ctx, `SELECT g.id, g.session_id, g.user_id, g.kind, g.launch_expires_at, g.redeemed_at, d.mesh_node_id
			FROM remote_grants g JOIN devices d ON d.id = g.device_id
			WHERE g.launch_hash = $1 FOR UPDATE OF g`, hash).
			Scan(&grantID, &sessionID, &userID, &kind, &expires, &redeemed, &nodeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGrantInvalid
		}
		if err != nil {
			return err
		}
		if redeemed != nil || !now.Before(expires) || nodeID == "" {
			return ErrGrantInvalid
		}
		if ok, err := sessionValid(ctx, tx, sessionID, now); err != nil || !ok {
			if err != nil {
				return err
			}
			return ErrGrantInvalid
		}
		if _, err := tx.Exec(ctx, `UPDATE remote_grants SET redeemed_at = $2, cookie_hash = $3 WHERE id = $1`,
			grantID, now, cookieHash); err != nil {
			return err
		}
		out = &Redemption{SessionID: sessionID, Cookie: cookie}
		return nil
	})
	if err != nil {
		return nil, err
	}
	login, err := meshcentral.LoginToken(s.cfg.LoginKey, accountID(userID), now)
	if err != nil {
		return nil, err
	}
	if out.Target, err = launchTarget(nodeID, Kind(kind), login); err != nil {
		return nil, err
	}
	return out, nil
}

// meshNodeID matches a MeshCentral node ID after its "node//" prefix:
// base64 with '@' and '$' in place of '+' and '/'.
var meshNodeID = regexp.MustCompile(`^[A-Za-z0-9@$]{1,128}$`)

// launchTarget is the MeshCentral page that signs the browser in and opens
// the device in the session's view. MeshCentral's page reads its URL
// arguments without decoding them and discards any value containing '%', so
// the node ID goes in as is: its characters are all allowed in a query
// (RFC 3986). The login token is only read by the server, which decodes it.
func launchTarget(nodeID string, kind Kind, login string) (string, error) {
	node := strings.TrimPrefix(nodeID, "node//")
	if !meshNodeID.MatchString(node) {
		return "", fmt.Errorf("remote: unexpected MeshCentral node ID %q", nodeID)
	}
	target := "/?gotonode=" + node + "&viewmode=" + kind.viewMode() + "&hide=" + hideFlags
	if kind == KindRDP {
		// Read by EasyRMM's session view tuning, which opens RDP instead of
		// MeshAgent's desktop (ADR-0026).
		target += "&rdp=1"
	}
	return target + "&login=" + url.QueryEscape(login), nil
}

// CheckCookie returns the EasyRMM session a gateway cookie belongs to, if
// that session is still valid.
func (s *Service) CheckCookie(ctx context.Context, cookie string) (uuid.UUID, error) {
	if cookie == "" || len(cookie) > 128 {
		return uuid.Nil, ErrGrantInvalid
	}
	var sessionID uuid.UUID
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT session_id FROM remote_grants WHERE cookie_hash = $1`, hashSecret(cookie)).Scan(&sessionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGrantInvalid
		}
		if err != nil {
			return err
		}
		ok, err := sessionValid(ctx, tx, sessionID, s.now())
		if err != nil {
			return err
		}
		if !ok {
			return ErrGrantInvalid
		}
		return nil
	})
	return sessionID, err
}

// SessionGranted reports whether an EasyRMM session opened a remote session
// of a kind on a device, given its MeshCentral node ID. The gateway lets a
// browser's relay connections reach only such devices, for that kind.
func (s *Service) SessionGranted(ctx context.Context, session uuid.UUID, nodeID string, kind Kind) (bool, error) {
	var ok bool
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM remote_grants g JOIN devices d ON d.id = g.device_id
			WHERE g.session_id = $1 AND g.redeemed_at IS NOT NULL AND d.mesh_node_id = $2 AND g.kind = $3)`,
			session, nodeID, string(kind)).Scan(&ok)
	})
	return ok, err
}

// SessionsValid reports which of the given EasyRMM sessions are still valid.
func (s *Service) SessionsValid(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]bool, error) {
	out := make(map[uuid.UUID]bool, len(ids))
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.id FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.id = ANY ($1) AND s.state = 'active' AND s.revoked_at IS NULL
			  AND s.expires_at > $2 AND s.idle_expires_at > $2 AND u.status = 'active'`, ids, s.now())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out[id] = true
		}
		return rows.Err()
	})
	return out, err
}

func sessionValid(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, now time.Time) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id = $1 AND s.state = 'active' AND s.revoked_at IS NULL
		  AND s.expires_at > $2 AND s.idle_expires_at > $2 AND u.status = 'active')`, sessionID, now).Scan(&ok)
	return ok, err
}

// CleanupGrants removes grants whose session has ended and launch links
// never opened, after a day.
func (s *Service) CleanupGrants(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM remote_grants g WHERE g.created_at < now() - interval '1 day'
			AND (g.redeemed_at IS NULL OR NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id = g.session_id
			     AND s.revoked_at IS NULL AND s.expires_at > now()))`)
		return err
	})
}

func newSecret() (string, []byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	t := base64.RawURLEncoding.EncodeToString(b)
	return t, hashSecret(t), nil
}

func hashSecret(t string) []byte {
	h := sha256.Sum256([]byte(t))
	return h[:]
}

// rdpGrant finds the redeemed RDP grant a session holds on a device, by its
// MeshCentral node ID: whose it is, the device and organization it is for and
// where the browser came from. The gateway takes the identity of a saved
// credential's use from here, never from the browser's message (ADR-0079).
func (s *Service) rdpGrant(ctx context.Context, session uuid.UUID, nodeID string) (rdpGrant, error) {
	var out rdpGrant
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		var ip *string
		err := tx.QueryRow(ctx, `SELECT g.id, g.user_id, g.organization_id, g.site_id, g.device_id, host(g.source_ip)
			FROM remote_grants g JOIN devices d ON d.id = g.device_id
			WHERE g.session_id = $1 AND g.redeemed_at IS NOT NULL AND d.mesh_node_id = $2 AND g.kind = $3
			ORDER BY g.redeemed_at DESC LIMIT 1`, session, nodeID, string(KindRDP)).
			Scan(&out.Grant, &out.User, &out.Organization, &out.Site, &out.Device, &ip)
		if ip != nil {
			out.ClientIP = *ip
		}
		return err
	})
	return out, err
}
