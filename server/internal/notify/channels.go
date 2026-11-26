package notify

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/addrpolicy"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Channel states, as the console shows them.
const (
	StateSending = "sending"
	StateFailing = "failing"
	StateWaiting = "waiting_for_approval"
	StateOff     = "off"
)

var (
	// ErrChannelQuota is an organization at its quota of channels.
	ErrChannelQuota = apperr.Conflict("channel_quota", "This organization has reached its limit of notification channels. Delete one first, or ask a super administrator to raise the limit.")
	// ErrNameTaken is a name already used by another of the owner's channels.
	ErrNameTaken = apperr.Invalid("name", "Another channel of this owner has that name.")
)

// Approval is a private destination's approval, as the console shows it.
type Approval struct {
	State       string     `json:"state"`
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	Proposed    []string   `json:"proposed"`
	Prefixes    []string   `json:"prefixes"`
	RequestedAt time.Time  `json:"requestedAt"`
	ApprovedAt  *time.Time `json:"approvedAt,omitempty"`
}

// SharedOrg is an organization a platform channel is shared with.
type SharedOrg struct {
	OrganizationID uuid.UUID `json:"organizationId"`
	SharedAt       time.Time `json:"sharedAt"`
}

// Channel is a channel as the console shows it. A platform channel shared
// with an organization shows that organization its name and kind only.
type Channel struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID *uuid.UUID `json:"organizationId"`
	Platform       bool       `json:"platform"`
	Shared         bool       `json:"shared"`
	Kind           string     `json:"kind"`
	Name           string     `json:"name"`
	Enabled        bool       `json:"enabled"`

	State         string      `json:"state,omitempty"`
	Recipients    []string    `json:"recipients,omitempty"`
	Host          string      `json:"host,omitempty"`
	Port          int         `json:"port,omitempty"`
	HasAuthority  bool        `json:"hasAuthority,omitempty"`
	LegacyHeaders bool        `json:"legacyHeaders,omitempty"`
	LastError     string      `json:"lastError,omitempty"`
	FailingSince  *time.Time  `json:"failingSince,omitempty"`
	LastSuccessAt *time.Time  `json:"lastSuccessAt,omitempty"`
	LastAttemptAt *time.Time  `json:"lastAttemptAt,omitempty"`
	Pending       int         `json:"pending"`
	Approval      *Approval   `json:"approval,omitempty"`
	SharedWith    []SharedOrg `json:"sharedWith,omitempty"`
}

// ChannelInput is what a channel is made or changed with. On change, a
// field left out stays as it was.
type ChannelInput struct {
	// OrganizationID is the owner when making a channel: nil for the
	// platform's. It cannot be changed.
	OrganizationID *uuid.UUID `json:"organizationId,omitempty"`
	Kind           string     `json:"kind,omitempty"`
	Name           *string    `json:"name,omitempty"`
	Enabled        *bool      `json:"enabled,omitempty"`
	Recipients     []string   `json:"recipients,omitempty"`
	// URL is a webhook's address; changing its host or port clears the
	// approval.
	URL *string `json:"url,omitempty"`
	// TrustedAuthority is a PEM certificate authority to trust for a
	// receiver with a private certificate; an empty string removes it.
	TrustedAuthority *string `json:"trustedAuthority,omitempty"`
	// LegacyHeaders can only be turned off (ADR-0053).
	LegacyHeaders *bool `json:"legacyHeaders,omitempty"`
}

func urlAD(id uuid.UUID) []byte    { return []byte("notification_channel:" + id.String() + ":url") }
func secretAD(id uuid.UUID) []byte { return []byte("notification_channel:" + id.String() + ":secret") }

// authorize checks the caller may manage a channel of this owner. A caller
// with no right to the owner is told the channel does not exist.
func authorize(c access.Caller, owner uuid.UUID) error {
	var ok bool
	if owner == uuid.Nil {
		ok = c.CanGlobal(rbac.PermNotificationManage)
	} else {
		ok = c.Can(rbac.PermNotificationManage, rbac.Org(owner))
	}
	if !ok {
		return apperr.NotFound()
	}
	return nil
}

// ownerOf finds a channel's owner and kind.
func (s *Service) ownerOf(ctx context.Context, id uuid.UUID) (owner uuid.UUID, kind string, err error) {
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT owner, kind FROM notification_channels WHERE id = $1`, id).Scan(&owner, &kind)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", apperr.NotFound()
	}
	return owner, kind, err
}

// manage finds the channel and checks the caller may manage it.
func (s *Service) manage(ctx context.Context, c access.Caller, id uuid.UUID) (owner uuid.UUID, kind string, err error) {
	if owner, kind, err = s.ownerOf(ctx, id); err != nil {
		return uuid.Nil, "", err
	}
	return owner, kind, authorize(c, owner)
}

func cleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", apperr.Invalid("name", "Enter a name.")
	case len([]rune(name)) > MaxNameLength:
		return "", apperr.Invalid("name", "The name can be at most 100 characters.")
	case strings.ContainsFunc(name, unicode.IsControl):
		return "", apperr.Invalid("name", "The name cannot hold control characters.")
	}
	return name, nil
}

func cleanRecipients(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !mailer.BareAddress(r) {
			return nil, apperr.Invalid("recipients", fmt.Sprintf("%q is not an email address.", r))
		}
		if k := strings.ToLower(r); !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	if len(out) == 0 || len(out) > MaxRecipients {
		return nil, apperr.Invalid("recipients", "An email channel has 1 to 20 recipients.")
	}
	return out, nil
}

// cleanAuthority checks a PEM certificate authority.
func cleanAuthority(pemText string) (string, error) {
	pemText = strings.TrimSpace(pemText)
	if pemText == "" {
		return "", nil
	}
	if len(pemText) > 32<<10 {
		return "", apperr.Invalid("trustedAuthority", "The certificate authority is too long.")
	}
	rest, n := []byte(pemText), 0
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return "", apperr.Invalid("trustedAuthority", "Only certificates belong here, never a private key.")
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return "", apperr.Invalid("trustedAuthority", "That is not a certificate.")
		}
		n++
	}
	if n == 0 {
		return "", apperr.Invalid("trustedAuthority", "Paste the certificate authority as PEM, from -----BEGIN CERTIFICATE-----.")
	}
	return pemText + "\n", nil
}

func (s *Service) checkURL(raw string) (addrpolicy.Destination, error) {
	d, err := addrpolicy.ParseURL(raw)
	if err != nil {
		return d, apperr.Invalid("url", err.Error())
	}
	for _, n := range s.env.Snapshot().Names {
		if n == d.Host {
			return d, apperr.Invalid("url", "That is one of this server's own names. EasyRMM does not send to itself.")
		}
	}
	return d, nil
}

func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create makes a channel. The owner is the organization named in the input,
// or the platform; it never changes.
func (s *Service) Create(ctx context.Context, c access.Caller, in ChannelInput) (Channel, error) {
	owner := uuid.Nil
	if in.OrganizationID != nil {
		owner = *in.OrganizationID
	}
	if err := authorize(c, owner); err != nil {
		return Channel{}, err
	}
	name := ""
	if in.Name != nil {
		name = *in.Name
	}
	name, err := cleanName(name)
	if err != nil {
		return Channel{}, err
	}
	id := uuid.New()
	recipients := []string{}
	var host string
	var port int
	var sealedURL, sealedSecret, authority string
	switch in.Kind {
	case KindEmail:
		if recipients, err = cleanRecipients(in.Recipients); err != nil {
			return Channel{}, err
		}
	case KindWebhook:
		raw := ""
		if in.URL != nil {
			raw = *in.URL
		}
		d, err := s.checkURL(raw)
		if err != nil {
			return Channel{}, err
		}
		host, port = d.Host, d.Port
		if sealedURL, err = s.sealer.Seal([]byte(strings.TrimSpace(raw)), urlAD(id)); err != nil {
			return Channel{}, err
		}
		secret, err := newSecret()
		if err != nil {
			return Channel{}, err
		}
		if sealedSecret, err = s.sealer.Seal([]byte(secret), secretAD(id)); err != nil {
			return Channel{}, err
		}
		if in.TrustedAuthority != nil {
			if authority, err = cleanAuthority(*in.TrustedAuthority); err != nil {
				return Channel{}, err
			}
		}
	default:
		return Channel{}, apperr.Invalid("kind", "A channel is an email or a webhook; Slack and Microsoft Teams come later.")
	}
	enabled := in.Enabled == nil || *in.Enabled
	// At platform scope, with the organization's creations serialized: the
	// quota is the platform's to read, and the caller has been authorized.
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if owner != uuid.Nil {
			if err := lockChannel(ctx, tx, owner); err != nil {
				return err
			}
			var have int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM notification_channels WHERE owner = $1`, owner).Scan(&have); err != nil {
				return err
			}
			q, err := quotaOf(ctx, tx, owner)
			if err != nil {
				return err
			}
			if have >= q.Channels {
				return ErrChannelQuota
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channels (id, organization_id, owner, kind, name, enabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, orgPtr(owner), owner, in.Kind, name, enabled, actorID(c.Actor)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO notification_channel_details (channel_id, owner, recipients, webhook_host, webhook_port, sealed_url, sealed_secret, trusted_authority)
			VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, 0), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''))`,
			id, owner, recipients, host, port, sealedURL, sealedSecret, authority)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionCreate, OrganizationID: owner, TargetType: "notification_channel",
			TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"kind": in.Kind, "name": name, "host": host, "port": port, "recipients": len(recipients)}})
	})
	if err != nil {
		return Channel{}, mapChannelErr(err)
	}
	return s.get(ctx, c, id)
}

func mapChannelErr(err error) error {
	if database.IsUniqueViolation(err) && database.ConstraintName(err) == "notification_channels_name" {
		return ErrNameTaken
	}
	return err
}

// Update changes a channel. A webhook's new URL replaces the sealed one;
// changing its host or port clears the approval and closes the transport.
func (s *Service) Update(ctx context.Context, c access.Caller, id uuid.UUID, in ChannelInput) (Channel, error) {
	owner, kind, err := s.manage(ctx, c, id)
	if err != nil {
		return Channel{}, err
	}
	changed := map[string]any{}
	var name *string
	if in.Name != nil {
		n, err := cleanName(*in.Name)
		if err != nil {
			return Channel{}, err
		}
		name = &n
		changed["name"] = n
	}
	var recipients []string
	if in.Recipients != nil {
		if kind != KindEmail {
			return Channel{}, apperr.Invalid("recipients", "Only an email channel has recipients.")
		}
		if recipients, err = cleanRecipients(in.Recipients); err != nil {
			return Channel{}, err
		}
		changed["recipients"] = len(recipients)
	}
	var newURL, newHost string
	var newPort int
	if in.URL != nil {
		if kind != KindWebhook {
			return Channel{}, apperr.Invalid("url", "Only a webhook has a web address.")
		}
		d, err := s.checkURL(*in.URL)
		if err != nil {
			return Channel{}, err
		}
		if newURL, err = s.sealer.Seal([]byte(strings.TrimSpace(*in.URL)), urlAD(id)); err != nil {
			return Channel{}, err
		}
		newHost, newPort = d.Host, d.Port
		changed["host"], changed["port"] = d.Host, d.Port
	}
	var authority *string
	if in.TrustedAuthority != nil {
		if kind != KindWebhook {
			return Channel{}, apperr.Invalid("trustedAuthority", "Only a webhook has a certificate authority.")
		}
		a, err := cleanAuthority(*in.TrustedAuthority)
		if err != nil {
			return Channel{}, err
		}
		authority = &a
		changed["trustedAuthority"] = a != ""
	}
	if in.LegacyHeaders != nil {
		if *in.LegacyHeaders {
			return Channel{}, apperr.Invalid("legacyHeaders", "The X-EasyPatch headers can only be turned off, never on.")
		}
		changed["legacyHeaders"] = false
	}
	if in.Enabled != nil {
		changed["enabled"] = *in.Enabled
	}
	err = s.db.InTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		if err := lockChannel(ctx, tx, id); err != nil {
			return err
		}
		if name != nil || in.Enabled != nil {
			if _, err := tx.Exec(ctx, `UPDATE notification_channels SET name = coalesce($2, name), enabled = coalesce($3, enabled) WHERE id = $1`,
				id, name, in.Enabled); err != nil {
				return err
			}
		}
		bump := in.Enabled != nil || authority != nil || in.LegacyHeaders != nil
		if recipients != nil {
			if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET recipients = $2 WHERE channel_id = $1`, id, recipients); err != nil {
				return err
			}
		}
		if authority != nil {
			if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET trusted_authority = NULLIF($2, '') WHERE channel_id = $1`, id, *authority); err != nil {
				return err
			}
		}
		if in.LegacyHeaders != nil {
			if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET legacy_headers = false WHERE channel_id = $1`, id); err != nil {
				return err
			}
		}
		if newURL != "" {
			var oldHost string
			var oldPort int
			if err := tx.QueryRow(ctx, `SELECT coalesce(webhook_host, ''), coalesce(webhook_port, 0) FROM notification_channel_details WHERE channel_id = $1`, id).Scan(&oldHost, &oldPort); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET sealed_url = $2, webhook_host = $3, webhook_port = $4,
				failing = false, failing_since = NULL, failures_in_row = 0, last_error = NULL WHERE channel_id = $1`, id, newURL, newHost, newPort); err != nil {
				return err
			}
			bump = true
			if oldHost != newHost || oldPort != newPort {
				// A new destination is a new approval.
				if _, err := tx.Exec(ctx, `DELETE FROM notification_channel_approvals WHERE channel_id = $1`, id); err != nil {
					return err
				}
				if err := resolveNotice(ctx, tx, orgPtr(owner), NoticeWaitingApproval, id.String()); err != nil {
					return err
				}
			}
		}
		if bump {
			if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET generation = generation + 1 WHERE channel_id = $1`, id); err != nil {
				return err
			}
		}
		if in.Enabled != nil && !*in.Enabled {
			// Turning a channel off drops its pending deliveries, recorded as not sent.
			if err := dropPending(ctx, tx, id, uuid.Nil, "The channel was turned off."); err != nil {
				return err
			}
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionUpdate, OrganizationID: owner, TargetType: "notification_channel",
			TargetID: id.String(), Outcome: audit.Success, Details: changed})
	})
	if err != nil {
		return Channel{}, mapChannelErr(err)
	}
	s.dropTransport(id)
	return s.get(ctx, c, id)
}

// dropPending ends a channel's pending deliveries as dropped; with org set,
// only those charged to that organization.
func dropPending(ctx context.Context, tx pgx.Tx, channel uuid.UUID, org uuid.UUID, why string) error {
	_, err := tx.Exec(ctx, `UPDATE notification_deliveries SET status = 'dropped', ended_at = now(), lease_until = NULL, last_error = $3
		WHERE channel_id = $1 AND status = 'pending' AND ($2 = '00000000-0000-0000-0000-000000000000'::uuid OR charged_org = $2)`,
		channel, org, why)
	return err
}

// Delete removes a channel, and with it its pending deliveries.
func (s *Service) Delete(ctx context.Context, c access.Caller, id uuid.UUID) error {
	owner, _, err := s.manage(ctx, c, id)
	if err != nil {
		return err
	}
	err = s.db.InTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		if err := lockChannel(ctx, tx, id); err != nil {
			return err
		}
		var name string
		if err := tx.QueryRow(ctx, `SELECT name FROM notification_channels WHERE id = $1`, id).Scan(&name); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM notification_deliveries WHERE channel_id = $1 AND status = 'pending'`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1`, id); err != nil {
			return err
		}
		if err := s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionDelete, OrganizationID: owner, TargetType: "notification_channel",
			TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"name": name}}); err != nil {
			return err
		}
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.NotFound()
	}
	if err != nil {
		return err
	}
	// The notices about it are about nothing now.
	_ = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, k := range []string{NoticeChannelFailing, NoticeNotSent, NoticeWaitingApproval} {
			if err := resolveNotice(ctx, tx, orgPtr(owner), k, id.String()); err != nil {
				return err
			}
		}
		return nil
	})
	s.dropTransport(id)
	return nil
}

// channelRow is one channel as the queries read it.
type channelRow struct {
	Channel
	owner uuid.UUID
}

const channelSelect = `SELECT c.id, c.owner, c.kind, c.name, c.enabled,
	d.recipients, coalesce(d.webhook_host, ''), coalesce(d.webhook_port, 0), d.trusted_authority IS NOT NULL, coalesce(d.legacy_headers, false),
	coalesce(d.failing, false), d.failing_since, coalesce(d.last_error, ''), d.last_success_at, d.last_attempt_at,
	d.channel_id IS NOT NULL,
	(SELECT count(*) FROM notification_deliveries q WHERE q.channel_id = c.id AND q.status = 'pending' AND q.kind <> 'test'),
	a.state, a.host, a.port, a.proposed, a.prefixes, a.requested_at, a.approved_at
FROM notification_channels c
LEFT JOIN notification_channel_details d ON d.channel_id = c.id
LEFT JOIN notification_channel_approvals a ON a.channel_id = c.id`

func scanChannel(rows pgx.Rows) (channelRow, error) {
	var r channelRow
	var recips []string
	var failing, hasDetails bool
	var aState, aHost *string
	var aPort *int
	var aProposed, aPrefixes []string
	var aReq, aAt *time.Time
	if err := rows.Scan(&r.ID, &r.owner, &r.Kind, &r.Name, &r.Enabled, &recips, &r.Host, &r.Port, &r.HasAuthority, &r.LegacyHeaders,
		&failing, &r.FailingSince, &r.LastError, &r.LastSuccessAt, &r.LastAttemptAt, &hasDetails, &r.Pending,
		&aState, &aHost, &aPort, &aProposed, &aPrefixes, &aReq, &aAt); err != nil {
		return r, err
	}
	r.OrganizationID = orgPtr(r.owner)
	r.Platform = r.owner == uuid.Nil
	if !hasDetails {
		// An organization looking at a shared platform channel: name and kind only.
		r.Shared, r.Pending, r.Host, r.Port = true, 0, "", 0
		r.State, r.LastError, r.FailingSince, r.LastSuccessAt, r.LastAttemptAt = "", "", nil, nil, nil
		return r, nil
	}
	r.Recipients = recips
	switch {
	case !r.Enabled:
		r.State = StateOff
	case aState != nil && *aState == "requested":
		r.State = StateWaiting
	case failing:
		r.State = StateFailing
	default:
		r.State = StateSending
	}
	if aState != nil {
		r.Approval = &Approval{State: *aState, Host: *aHost, Port: *aPort, Proposed: aProposed, Prefixes: aPrefixes, RequestedAt: *aReq, ApprovedAt: aAt}
	}
	return r, nil
}

func (s *Service) list(ctx context.Context, scope database.Scope, where string, args ...any) ([]Channel, error) {
	out := []Channel{}
	err := s.db.ReadTx(ctx, scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, channelSelect+" "+where+" ORDER BY c.owner <> '00000000-0000-0000-0000-000000000000', lower(c.name), c.id", args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanChannel(rows)
			if err != nil {
				return err
			}
			out = append(out, r.Channel)
		}
		return rows.Err()
	})
	return out, err
}

// List lists channels. With an organization, that organization's own and the
// platform channels shared with it; with none, a super administrator sees
// every owner's.
func (s *Service) List(ctx context.Context, c access.Caller, org *uuid.UUID) ([]Channel, error) {
	if org == nil {
		if err := authorize(c, uuid.Nil); err != nil {
			return nil, err
		}
		out, err := s.list(ctx, database.System, "")
		if err != nil {
			return nil, err
		}
		return s.withShares(ctx, out)
	}
	if err := authorize(c, *org); err != nil {
		return nil, err
	}
	return s.list(ctx, ownerScope(*org), "")
}

func (s *Service) get(ctx context.Context, c access.Caller, id uuid.UUID) (Channel, error) {
	owner, _, err := s.manage(ctx, c, id)
	if err != nil {
		return Channel{}, err
	}
	out, err := s.list(ctx, ownerScope(owner), "WHERE c.id = $1", id)
	if err != nil {
		return Channel{}, err
	}
	if len(out) == 0 {
		return Channel{}, apperr.NotFound()
	}
	if out, err = s.withShares(ctx, out); err != nil {
		return Channel{}, err
	}
	return out[0], nil
}

// Get returns one channel the caller manages.
func (s *Service) Get(ctx context.Context, c access.Caller, id uuid.UUID) (Channel, error) {
	return s.get(ctx, c, id)
}

// withShares adds, to each platform channel, who it is shared with: seen by
// super administrators only.
func (s *Service) withShares(ctx context.Context, in []Channel) ([]Channel, error) {
	has := false
	for _, ch := range in {
		has = has || ch.Platform
	}
	if !has {
		return in, nil
	}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT channel_id, organization_id, shared_at FROM notification_channel_shares ORDER BY shared_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		byID := map[uuid.UUID][]SharedOrg{}
		for rows.Next() {
			var ch uuid.UUID
			var so SharedOrg
			if err := rows.Scan(&ch, &so.OrganizationID, &so.SharedAt); err != nil {
				return err
			}
			byID[ch] = append(byID[ch], so)
		}
		for i := range in {
			in[i].SharedWith = byID[in[i].ID]
		}
		return rows.Err()
	})
	return in, err
}

// Share shares a platform channel with an organization.
func (s *Service) Share(ctx context.Context, c access.Caller, channel, org uuid.UUID) error {
	owner, _, err := s.manage(ctx, c, channel)
	if err != nil {
		return err
	}
	if owner != uuid.Nil {
		return apperr.Conflict("not_a_platform_channel", "Only the platform's channels are shared. An organization's own are its own.")
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var name string
		if err := tx.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, org).Scan(&name); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.Invalid("organizationId", "That organization does not exist.")
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channel_shares (channel_id, organization_id, shared_by) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, channel, org, actorID(c.Actor)); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionShare, OrganizationID: org, TargetType: "notification_channel",
			TargetID: channel.String(), Outcome: audit.Success, Details: map[string]any{"organization": name}})
	})
}

// Unshare takes a platform channel back from an organization: what is
// pending to it for that organization is dropped.
func (s *Service) Unshare(ctx context.Context, c access.Caller, channel, org uuid.UUID) error {
	owner, _, err := s.manage(ctx, c, channel)
	if err != nil {
		return err
	}
	if owner != uuid.Nil {
		return apperr.NotFound()
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := lockChannel(ctx, tx, channel); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM notification_channel_shares WHERE channel_id = $1 AND organization_id = $2`, channel, org)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.NotFound()
		}
		if err := dropPending(ctx, tx, channel, org, "The channel is no longer shared with this organization."); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionUnshare, OrganizationID: org, TargetType: "notification_channel",
			TargetID: channel.String(), Outcome: audit.Success})
	})
}

// Secrets are a webhook's address and signing secret, shown again.
type Secrets struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
}

// Reveal answers a webhook's address and signing secret to whoever manages
// the channel, and records that it did. A shared platform channel is never
// revealed to an organization: the caller must manage its owner.
func (s *Service) Reveal(ctx context.Context, c access.Caller, id uuid.UUID) (Secrets, error) {
	owner, kind, err := s.manage(ctx, c, id)
	if err != nil {
		return Secrets{}, err
	}
	if kind != KindWebhook {
		return Secrets{}, apperr.Conflict("nothing_to_reveal", "Only a webhook has a secret to show.")
	}
	var out Secrets
	err = s.db.InTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		var u, sec string
		if err := tx.QueryRow(ctx, `SELECT sealed_url, sealed_secret FROM notification_channel_details WHERE channel_id = $1`, id).Scan(&u, &sec); err != nil {
			return err
		}
		ub, err := s.sealer.Open(u, urlAD(id))
		if err != nil {
			return err
		}
		sb, err := s.sealer.Open(sec, secretAD(id))
		if err != nil {
			return err
		}
		out = Secrets{URL: string(ub), Secret: string(sb)}
		// The audit record says that it was shown, never what.
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionReveal, OrganizationID: owner, TargetType: "notification_channel",
			TargetID: id.String(), Outcome: audit.Success})
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Secrets{}, apperr.NotFound()
	}
	return out, err
}

// RotateSecret replaces a webhook's signing secret at once.
func (s *Service) RotateSecret(ctx context.Context, c access.Caller, id uuid.UUID) error {
	owner, kind, err := s.manage(ctx, c, id)
	if err != nil {
		return err
	}
	if kind != KindWebhook {
		return apperr.Conflict("nothing_to_rotate", "Only a webhook has a signing secret.")
	}
	secret, err := newSecret()
	if err != nil {
		return err
	}
	sealed, err := s.sealer.Seal([]byte(secret), secretAD(id))
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET sealed_secret = $2 WHERE channel_id = $1`, id, sealed); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionRotate, OrganizationID: owner, TargetType: "notification_channel",
			TargetID: id.String(), Outcome: audit.Success})
	})
}

// RequestApproval asks a super administrator to approve a webhook's private
// destination: the proposed addresses are what the host resolves to now.
func (s *Service) RequestApproval(ctx context.Context, c access.Caller, id uuid.UUID) (Approval, error) {
	owner, kind, err := s.manage(ctx, c, id)
	if err != nil {
		return Approval{}, err
	}
	if kind != KindWebhook || owner == uuid.Nil {
		return Approval{}, apperr.Conflict("approval_not_needed", "Only an organization's webhook needs an approval for a private destination.")
	}
	a, err := s.ask(ctx, owner, id, c.Actor)
	if err != nil {
		return Approval{}, err
	}
	return a, nil
}

// ask records the request (or finds it), in the owner's scope: an
// organization's scope may only ask.
func (s *Service) ask(ctx context.Context, owner, id uuid.UUID, actor audit.Actor) (Approval, error) {
	var host string
	var port int
	if err := s.db.ReadTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT webhook_host, webhook_port FROM notification_channel_details WHERE channel_id = $1`, id).Scan(&host, &port)
	}); err != nil {
		return Approval{}, err
	}
	proposed := s.proposed(ctx, host)
	var out Approval
	err := s.db.InTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		var state string
		err := tx.QueryRow(ctx, `SELECT state FROM notification_channel_approvals WHERE channel_id = $1 AND host = $2 AND port = $3`, id, host, port).Scan(&state)
		switch {
		case err == nil && state == "approved":
			return apperr.Conflict("already_approved", "This destination is already approved.")
		case err == nil:
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM notification_channel_approvals WHERE channel_id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_channel_approvals (channel_id, owner, host, port, proposed, requested_by)
			VALUES ($1, $2, $3, $4, $5, $6)`, id, owner, host, port, proposed, actorID(actor)); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: ActionApprovalRequest, OrganizationID: owner, TargetType: "notification_channel",
			TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"host": host, "port": port, "proposed": proposed}})
	})
	if err != nil {
		return Approval{}, err
	}
	err = s.db.ReadTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, host, port, proposed, prefixes, requested_at, approved_at FROM notification_channel_approvals WHERE channel_id = $1`, id).
			Scan(&out.State, &out.Host, &out.Port, &out.Proposed, &out.Prefixes, &out.RequestedAt, &out.ApprovedAt)
	})
	return out, err
}

// proposed lists the addresses a host resolves to, each as a single
// address: what a super administrator is shown to approve.
func (s *Service) proposed(ctx context.Context, host string) []string {
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		look := s.resolve
		if look == nil {
			look = func(ctx context.Context, h string) ([]netip.Addr, error) { return netLookup(ctx, h) }
		}
		addrs, _ = look(cctx, host)
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.Unmap().String())
	}
	return out
}

// Approve approves a webhook's private destination: one or more prefixes the
// host may be dialed at, at least one containing an address it resolves to.
// Super administrators only. Nothing approves what is always refused.
func (s *Service) Approve(ctx context.Context, c access.Caller, id uuid.UUID, prefixes []string) (Approval, error) {
	owner, kind, err := s.ownerOf(ctx, id)
	if err != nil {
		return Approval{}, err
	}
	if err := authorize(c, uuid.Nil); err != nil {
		return Approval{}, err
	}
	if kind != KindWebhook || owner == uuid.Nil {
		return Approval{}, apperr.Conflict("approval_not_needed", "Only an organization's webhook needs an approval.")
	}
	ps, err := addrpolicy.ParsePrefixes(prefixes)
	if err != nil || len(ps) == 0 || len(ps) > 10 {
		return Approval{}, apperr.Invalid("prefixes", "Give 1 to 10 addresses or networks, such as 10.0.0.7 or 10.0.0.0/24.")
	}
	for _, p := range ps {
		if (p.Addr().Is4() && p.Bits() < 8) || (p.Addr().Is6() && p.Bits() < 32) {
			return Approval{}, apperr.Invalid("prefixes", fmt.Sprintf("%s is too wide to approve for one destination.", p))
		}
	}
	strs := make([]string, len(ps))
	for i, p := range ps {
		strs[i] = p.String()
	}
	var out Approval
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if err := lockChannel(ctx, tx, id); err != nil {
			return err
		}
		var proposed []string
		var host string
		var port int
		if err := tx.QueryRow(ctx, `SELECT proposed, host, port FROM notification_channel_approvals WHERE channel_id = $1`, id).Scan(&proposed, &host, &port); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return apperr.Conflict("no_approval_asked", "No approval is waiting for this channel.")
			}
			return err
		}
		covers := false
		for _, pa := range proposed {
			if a, err := netip.ParseAddr(pa); err == nil && containsAny(ps, a) {
				covers = true
			}
		}
		if !covers {
			return apperr.Invalid("prefixes", "Approve a network that holds an address the host resolves to.")
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_channel_approvals SET state = 'approved', prefixes = $2, approved_by = $3, approved_at = now() WHERE channel_id = $1`,
			id, strs, actorID(c.Actor)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET generation = generation + 1 WHERE channel_id = $1`, id); err != nil {
			return err
		}
		if err := resolveNotice(ctx, tx, orgPtr(owner), NoticeWaitingApproval, id.String()); err != nil {
			return err
		}
		// What waited for the approval is tried at once.
		if _, err := tx.Exec(ctx, `UPDATE notification_deliveries SET next_attempt_at = now() WHERE channel_id = $1 AND status = 'pending'`, id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionApprove, OrganizationID: owner, TargetType: "notification_channel",
			TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"host": host, "port": port, "prefixes": strs}})
	})
	if err != nil {
		return Approval{}, err
	}
	s.dropTransport(id)
	s.Kick()
	ch, err := s.get(ctx, c, id)
	if err != nil || ch.Approval == nil {
		return out, err
	}
	return *ch.Approval, nil
}

func containsAny(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// Withdraw takes an approval back, which closes the channel's transport at
// once; the organization's scope may do so too, for its own channel.
func (s *Service) Withdraw(ctx context.Context, c access.Caller, id uuid.UUID) error {
	owner, _, err := s.manage(ctx, c, id)
	if err != nil {
		return err
	}
	err = s.db.InTx(ctx, ownerScope(owner), func(tx pgx.Tx) error {
		if err := lockChannel(ctx, tx, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM notification_channel_approvals WHERE channel_id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return apperr.NotFound()
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_channel_details SET generation = generation + 1 WHERE channel_id = $1`, id); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: ActionWithdraw, OrganizationID: owner, TargetType: "notification_channel",
			TargetID: id.String(), Outcome: audit.Success})
	})
	if err != nil {
		return err
	}
	s.dropTransport(id)
	return nil
}

// ApprovalRequest is a request a super administrator is asked to decide.
type ApprovalRequest struct {
	ChannelID      uuid.UUID  `json:"channelId"`
	OrganizationID *uuid.UUID `json:"organizationId"`
	Name           string     `json:"name"`
	Host           string     `json:"host"`
	Port           int        `json:"port"`
	Proposed       []string   `json:"proposed"`
	RequestedAt    time.Time  `json:"requestedAt"`
}

// Requests lists the approvals waiting, for super administrators.
func (s *Service) Requests(ctx context.Context, c access.Caller) ([]ApprovalRequest, error) {
	if err := authorize(c, uuid.Nil); err != nil {
		return nil, err
	}
	out := []ApprovalRequest{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT a.channel_id, a.owner, c.name, a.host, a.port, a.proposed, a.requested_at
			FROM notification_channel_approvals a JOIN notification_channels c ON c.id = a.channel_id
			WHERE a.state = 'requested' ORDER BY a.requested_at`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r ApprovalRequest
			var owner uuid.UUID
			if err := rows.Scan(&r.ChannelID, &owner, &r.Name, &r.Host, &r.Port, &r.Proposed, &r.RequestedAt); err != nil {
				return err
			}
			r.OrganizationID = orgPtr(owner)
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}
