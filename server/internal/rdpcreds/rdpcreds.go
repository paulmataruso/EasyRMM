// Package rdpcreds stores the RDP credentials people choose to save for a
// device (ADR-0079). The password is sealed with the server's secrets key,
// bound to its row, device, scope and person; no call returns it. The only
// reader is OpenForSession, which the remote gateway calls to write the
// credential into the first message of an RDP session, so the browser never
// holds the password and MeshCentral never stores one.
package rdpcreds

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// Scopes of a credential. Only the personal scope is offered so far; the
// shared level (ADR-0079 slice 4) is not built and its rows are refused.
const (
	ScopeUser   = "user"
	ScopeDevice = "device"
)

// Limits on what a credential holds.
const (
	maxLabel    = 100
	maxDomain   = 255
	maxUsername = 255
	maxPassword = 1024
)

// Audit actions (ADR-0007, ADR-0079 section 6).
const (
	ActionCreated   = "rdp_credential.created"
	ActionReplaced  = "rdp_credential.replaced"
	ActionDeleted   = "rdp_credential.deleted"
	ActionUsed      = "rdp_credential.used"
	ActionUseDenied = "rdp_credential.use_denied"
	ActionPurged    = "rdp_credential.purged"
)

// Credential is what the API shows of a saved credential: never the password.
type Credential struct {
	ID         uuid.UUID  `json:"id"`
	DeviceID   uuid.UUID  `json:"deviceId"`
	Scope      string     `json:"scope"`
	Label      string     `json:"label"`
	Domain     string     `json:"domain"`
	Username   string     `json:"username"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
}

// SaveInput is a credential to save or replace. Password is the caller's
// byte slice; Save zeroes it.
type SaveInput struct {
	Label    string
	Domain   string
	Username string
	Password []byte
}

// Service saves, lists, deletes and opens credentials.
type Service struct {
	db        *database.DB
	audit     *audit.Logger
	sealer    *secrets.Sealer
	principal func(ctx context.Context, userID uuid.UUID) (*rbac.Principal, error)
	now       func() time.Time
}

// New builds the service. principal resolves a user's permissions for the
// gateway, which holds a session and no request (auth.Service.LoadPrincipal).
func New(db *database.DB, log *audit.Logger, sealer *secrets.Sealer, principal func(context.Context, uuid.UUID) (*rbac.Principal, error)) *Service {
	return &Service{db: db, audit: log, sealer: sealer, principal: principal, now: time.Now}
}

// associatedData binds a sealed password to its row, device, scope and
// person. The person is the user's UUID for the personal scope and "-" for
// the device scope, whose column is NULL.
func associatedData(id, device uuid.UUID, scope string, user *uuid.UUID) []byte {
	u := "-"
	if user != nil {
		u = user.String()
	}
	return []byte("rdp-credential:" + id.String() + ":" + device.String() + ":" + scope + ":" + u)
}

type deviceRow struct {
	id, org, site uuid.UUID
	name          string
	platform      string
}

// device finds a device the caller may see and may open remote desktop on.
func (s *Service) device(ctx context.Context, c access.Caller, id uuid.UUID) (*deviceRow, error) {
	if c.Principal == nil {
		return nil, apperr.Forbidden()
	}
	var d deviceRow
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT id, organization_id, site_id, name, platform FROM devices WHERE id = $1`, id).
			Scan(&d.id, &d.org, &d.site, &d.name, &d.platform)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	site := rbac.Site(d.org, d.site)
	if !c.Can(rbac.PermDeviceView, site) {
		return nil, apperr.NotFound()
	}
	return &d, nil
}

func (s *Service) requireSave(c access.Caller, d *deviceRow) error {
	site := rbac.Site(d.org, d.site)
	if err := c.Require(rbac.PermRemoteDesktop, site); err != nil {
		return err
	}
	if err := c.Require(rbac.PermRDPCredentialsSave, site); err != nil {
		return err
	}
	if !devscope.Allowed(d.org) {
		return apperr.Forbidden()
	}
	if d.platform != "windows" {
		return apperr.Invalid("device", "Saved RDP credentials are offered for Windows computers only.")
	}
	return nil
}

func (in *SaveInput) validate() error {
	f := apperr.Fields{}
	f.Check(len(in.Label) <= maxLabel && utf8.ValidString(in.Label), "label", "Use at most 100 characters.")
	f.Check(len(in.Domain) <= maxDomain && utf8.ValidString(in.Domain), "domain", "Use at most 255 characters.")
	f.Check(in.Username != "" && len(in.Username) <= maxUsername && utf8.ValidString(in.Username), "username", "Enter a user name of at most 255 characters.")
	ok := len(in.Password) > 0 && len(in.Password) <= maxPassword && utf8.Valid(in.Password)
	for _, b := range in.Password {
		ok = ok && b != 0
	}
	f.Check(ok, "password", "Enter the password (at most 1024 characters).")
	return f.Err()
}

// Save saves the caller's own credential for a device, or replaces the one
// they saved (the password is the only thing a replacement must repeat). The
// caller has already passed step-up (the API's job). In.Password is zeroed.
func (s *Service) Save(ctx context.Context, c access.Caller, deviceID uuid.UUID, in SaveInput) (*Credential, error) {
	defer clear(in.Password)
	d, err := s.device(ctx, c, deviceID)
	if err != nil {
		return nil, err
	}
	if err := s.requireSave(c, d); err != nil {
		s.denied(ctx, c, d, "save", err)
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	if in.Label == "" {
		in.Label = in.Username
	}
	user := c.Principal.UserID
	var out Credential
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		id, replaced := uuid.New(), false
		err := tx.QueryRow(ctx, `SELECT id FROM device_rdp_credentials WHERE device_id = $1 AND scope = 'user' AND user_id = $2 FOR UPDATE`,
			d.id, user).Scan(&id)
		switch {
		case err == nil:
			replaced = true
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		sealed, err := s.sealer.Seal(in.Password, associatedData(id, d.id, ScopeUser, &user))
		if err != nil {
			return fmt.Errorf("rdpcreds: sealing: %w", err)
		}
		const cols = `id, device_id, scope, label, domain, username, created_at, last_used_at`
		if replaced {
			err = tx.QueryRow(ctx, `UPDATE device_rdp_credentials SET label = $2, domain = $3, username = $4, sealed_password = $5,
					updated_at = now(), rotated_at = now() WHERE id = $1 RETURNING `+cols,
				id, in.Label, in.Domain, in.Username, sealed).
				Scan(&out.ID, &out.DeviceID, &out.Scope, &out.Label, &out.Domain, &out.Username, &out.CreatedAt, &out.LastUsedAt)
		} else {
			err = tx.QueryRow(ctx, `INSERT INTO device_rdp_credentials (id, device_id, organization_id, scope, user_id, label, domain, username, sealed_password, created_by)
					VALUES ($1, $2, $3, 'user', $4, $5, $6, $7, $8, $4) RETURNING `+cols,
				id, d.id, d.org, user, in.Label, in.Domain, in.Username, sealed).
				Scan(&out.ID, &out.DeviceID, &out.Scope, &out.Label, &out.Domain, &out.Username, &out.CreatedAt, &out.LastUsedAt)
		}
		if err != nil {
			return err
		}
		action := ActionCreated
		if replaced {
			action = ActionReplaced
		}
		return s.audit.Write(ctx, tx, s.event(c.Actor, d, action, audit.Success, &out, nil))
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns the caller's own credentials for a device (the personal scope
// is all there is so far), without passwords.
func (s *Service) List(ctx context.Context, c access.Caller, deviceID uuid.UUID) ([]Credential, error) {
	d, err := s.device(ctx, c, deviceID)
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermRemoteDesktop, rbac.Site(d.org, d.site)) || !devscope.Allowed(d.org) || d.platform != "windows" {
		return []Credential{}, nil
	}
	out := []Credential{}
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, device_id, scope, label, domain, username, created_at, last_used_at
			FROM device_rdp_credentials WHERE device_id = $1 AND scope = 'user' AND user_id = $2 ORDER BY label, id`,
			d.id, c.Principal.UserID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var cr Credential
			if err := rows.Scan(&cr.ID, &cr.DeviceID, &cr.Scope, &cr.Label, &cr.Domain, &cr.Username, &cr.CreatedAt, &cr.LastUsedAt); err != nil {
				return err
			}
			out = append(out, cr)
		}
		return rows.Err()
	})
	return out, err
}

// Delete removes the caller's own credential. The caller has passed step-up.
func (s *Service) Delete(ctx context.Context, c access.Caller, deviceID, id uuid.UUID) error {
	d, err := s.device(ctx, c, deviceID)
	if err != nil {
		return err
	}
	if err := s.requireSave(c, d); err != nil {
		s.denied(ctx, c, d, "delete", err)
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var cr Credential
		err := tx.QueryRow(ctx, `DELETE FROM device_rdp_credentials WHERE id = $1 AND device_id = $2 AND scope = 'user' AND user_id = $3
			RETURNING id, device_id, scope, label, domain, username, created_at, last_used_at`, id, d.id, c.Principal.UserID).
			Scan(&cr.ID, &cr.DeviceID, &cr.Scope, &cr.Label, &cr.Domain, &cr.Username, &cr.CreatedAt, &cr.LastUsedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.event(c.Actor, d, ActionDeleted, audit.Success, &cr, nil))
	})
}

func (s *Service) event(actor audit.Actor, d *deviceRow, action string, outcome audit.Outcome, cr *Credential, extra map[string]any) audit.Event {
	details := map[string]any{"device": d.name}
	if cr != nil {
		details["credentialId"] = cr.ID.String()
		details["scope"] = cr.Scope
		details["label"] = cr.Label
		details["username"] = cr.Username
		details["domain"] = cr.Domain
	}
	for k, v := range extra {
		details[k] = v
	}
	return audit.Event{
		Actor: actor, Action: action, OrganizationID: d.org, SiteID: d.site, DeviceID: d.id,
		TargetType: "device", TargetID: d.id.String(), Outcome: outcome, Details: details,
	}
}

// denied records a refused save or delete. A failed audit write is not a
// reason to change the answer.
func (s *Service) denied(ctx context.Context, c access.Caller, d *deviceRow, what string, why error) {
	_ = s.audit.Record(ctx, s.event(c.Actor, d, ActionUseDenied, audit.Denied, nil, map[string]any{"attempt": what, "reason": why.Error()}))
}

// Use is a request to open a credential for an RDP session. Every field comes
// from the relay's authenticated grant except CredentialID.
type Use struct {
	CredentialID uuid.UUID
	Session      uuid.UUID
	Grant        uuid.UUID
	User         uuid.UUID
	Organization uuid.UUID
	Site         uuid.UUID
	Device       uuid.UUID
	ClientIP     string
}

// Opened is an opened credential. The caller zeroes Password.
type Opened struct {
	Domain   string
	Username string
	Password []byte
}

// OpenForSession opens a credential for the session that asks, after
// checking that it is the person's own, on the device the grant is for, that
// the person is active and still holds remote desktop, that the
// organization is in the dev scope and that the session stepped up within
// the last auth.StepUpWindow. Every refusal and every use is audited.
func (s *Service) OpenForSession(ctx context.Context, u Use) (*Opened, error) {
	var (
		cr      Credential
		orgID   uuid.UUID
		owner   *uuid.UUID
		sealed  string
		devName string
	)
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT c.id, c.device_id, c.organization_id, c.scope, c.user_id, c.label, c.domain, c.username, c.sealed_password, d.name
			FROM device_rdp_credentials c JOIN devices d ON d.id = c.device_id WHERE c.id = $1`, u.CredentialID).
			Scan(&cr.ID, &cr.DeviceID, &orgID, &cr.Scope, &owner, &cr.Label, &cr.Domain, &cr.Username, &sealed, &devName)
	})
	d := &deviceRow{id: u.Device, org: u.Organization, site: u.Site, name: devName}
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, s.refuse(ctx, u, d, nil, "no such credential")
	case err != nil:
		return nil, err
	}
	var reason string
	switch {
	case cr.DeviceID != u.Device || orgID != u.Organization:
		reason = "credential is for another device"
	case cr.Scope != ScopeUser:
		reason = "shared credentials are not enabled"
	case owner == nil || *owner != u.User:
		reason = "credential belongs to another person"
	case !devscope.Allowed(orgID):
		reason = "organization is outside the dev scope"
	}
	if reason != "" {
		return nil, s.refuse(ctx, u, d, &cr, reason)
	}
	if reason, err = s.mayUse(ctx, u); err != nil {
		return nil, err
	}
	if reason != "" {
		return nil, s.refuse(ctx, u, d, &cr, reason)
	}
	pw, err := s.sealer.Open(sealed, associatedData(cr.ID, cr.DeviceID, cr.Scope, owner))
	if err != nil {
		return nil, s.refuse(ctx, u, d, &cr, "credential cannot be opened")
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE device_rdp_credentials SET last_used_at = now() WHERE id = $1`, cr.ID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, s.event(s.actor(u, ""), d, ActionUsed, audit.Success, &cr, map[string]any{
			"grantId": u.Grant.String(), "sessionId": u.Session.String(), "clientAddress": u.ClientIP,
		}))
	})
	if err != nil {
		clear(pw)
		return nil, err
	}
	return &Opened{Domain: cr.Domain, Username: cr.Username, Password: pw}, nil
}

// mayUse checks the person and the session: it returns why not, or "".
func (s *Service) mayUse(ctx context.Context, u Use) (string, error) {
	var status string
	var steppedUp *time.Time
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT u.status, s.stepped_up_at FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.id = $1 AND u.id = $2 AND s.revoked_at IS NULL AND s.expires_at > now() AND s.idle_expires_at > now()`, u.Session, u.User).Scan(&status, &steppedUp)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "session is not the person's, or has ended", nil
	}
	if err != nil {
		return "", err
	}
	if status != "active" {
		return "person is not active", nil
	}
	p, err := s.principal(ctx, u.User)
	if err != nil {
		return "", err
	}
	if !p.Can(rbac.PermRemoteDesktop, rbac.Site(u.Organization, u.Site)) {
		return "person no longer holds remote desktop", nil
	}
	now := s.now()
	if steppedUp == nil || steppedUp.After(now) || now.Sub(*steppedUp) >= auth.StepUpWindow {
		return "step-up is required", nil
	}
	return "", nil
}

// ErrRefused is what a refused use answers; the audit row says why.
var ErrRefused = errors.New("saved RDP credential refused")

func (s *Service) actor(u Use, label string) audit.Actor {
	a := audit.Actor{Type: audit.ActorUser, ID: u.User, Label: label}
	if ip, err := netip.ParseAddr(u.ClientIP); err == nil {
		a.SourceIP = ip
	}
	return a
}

// refuse audits a refused use and returns ErrRefused.
func (s *Service) refuse(ctx context.Context, u Use, d *deviceRow, cr *Credential, reason string) error {
	extra := map[string]any{"reason": reason, "grantId": u.Grant.String(), "sessionId": u.Session.String(), "clientAddress": u.ClientIP,
		"requestedCredentialId": u.CredentialID.String()}
	ev := s.event(s.actor(u, ""), d, ActionUseDenied, audit.Denied, cr, extra)
	if err := s.audit.Record(ctx, ev); err != nil {
		return fmt.Errorf("%w: %s (audit failed: %w)", ErrRefused, reason, err)
	}
	return fmt.Errorf("%w: %s", ErrRefused, reason)
}

// PurgeDevice deletes every credential saved for a device in tx and audits
// each one (ADR-0079 section 7), for a move between organizations. A device
// removal deletes them through the foreign key.
func PurgeDevice(ctx context.Context, tx pgx.Tx, log *audit.Logger, actor audit.Actor, deviceID, org, site uuid.UUID, deviceName, reason string) error {
	rows, err := tx.Query(ctx, `DELETE FROM device_rdp_credentials WHERE device_id = $1 RETURNING id, scope, label, domain, username`, deviceID)
	if err != nil {
		return err
	}
	var purged []Credential
	for rows.Next() {
		cr := Credential{DeviceID: deviceID}
		if err := rows.Scan(&cr.ID, &cr.Scope, &cr.Label, &cr.Domain, &cr.Username); err != nil {
			rows.Close()
			return err
		}
		purged = append(purged, cr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range purged {
		cr := &purged[i]
		err := log.Write(ctx, tx, audit.Event{
			Actor: actor, Action: ActionPurged, OrganizationID: org, SiteID: site, DeviceID: deviceID,
			TargetType: "device", TargetID: deviceID.String(), Outcome: audit.Success,
			Details: map[string]any{"device": deviceName, "credentialId": cr.ID.String(), "scope": cr.Scope, "label": cr.Label,
				"username": cr.Username, "domain": cr.Domain, "reason": reason},
		})
		if err != nil {
			return err
		}
	}
	return nil
}
