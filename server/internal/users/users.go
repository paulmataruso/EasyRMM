// Package users manages operator accounts and their role assignments.
//
// Accounts are platform-wide (one e-mail address, one password, one second
// factor) while access is granted per organization or site. An
// administrator sees the users who hold roles inside their scope, and may
// change an account only when every role it holds is one they could have
// granted themselves, so nobody can lock out or take over a user with wider
// access than their own.
package users

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// lockUserAdmin serializes changes that could remove the last super
// administrator.
const lockUserAdmin = 4417355204182

// Assignment is a role grant as shown to administrators.
type Assignment struct {
	Role             rbac.Role  `json:"role"`
	OrganizationID   *uuid.UUID `json:"organizationId,omitempty"`
	OrganizationName string     `json:"organizationName,omitempty"`
	SiteID           *uuid.UUID `json:"siteId,omitempty"`
	SiteName         string     `json:"siteName,omitempty"`
}

func (a Assignment) rbac() rbac.Assignment {
	out := rbac.Assignment{Role: a.Role}
	if a.OrganizationID != nil {
		out.OrganizationID = *a.OrganizationID
	}
	if a.SiteID != nil {
		out.SiteID = *a.SiteID
	}
	return out
}

func resourceOf(a rbac.Assignment) rbac.Resource {
	return rbac.Resource{OrganizationID: a.OrganizationID, SiteID: a.SiteID}
}

// User is an account as shown to administrators.
type User struct {
	ID          uuid.UUID    `json:"id"`
	Email       string       `json:"email"`
	DisplayName string       `json:"displayName"`
	Status      string       `json:"status"`
	MFAEnabled  bool         `json:"mfaEnabled"`
	PasswordSet bool         `json:"passwordSet"` // false until an invitation is accepted
	Locked      bool         `json:"locked"`
	LastLoginAt *time.Time   `json:"lastLoginAt"`
	CreatedAt   time.Time    `json:"createdAt"`
	Assignments []Assignment `json:"assignments"`
	// HiddenAssignments counts roles held outside the caller's view.
	HiddenAssignments int  `json:"hiddenAssignments"`
	CanManage         bool `json:"canManage"`
	IsSelf            bool `json:"isSelf"`
	all               []rbac.Assignment
}

// InviteInput creates an account.
type InviteInput struct {
	Email       string       `json:"email"`
	DisplayName string       `json:"displayName"`
	Assignments []Assignment `json:"assignments"`
}

// InviteResult reports how the invitation reaches the new user.
type InviteResult struct {
	User *User `json:"user"`
	// Link is returned only when it could not be e-mailed, so the
	// administrator can deliver it another way.
	Link    string `json:"link,omitempty"`
	Emailed bool   `json:"emailed"`
}

// ListQuery filters the user list.
type ListQuery struct {
	Search         string
	OrganizationID uuid.UUID
	After          string // cursor from a previous page
	Limit          int
}

// Service implements user administration.
type Service struct {
	db     *database.DB
	audit  *audit.Logger
	auth   *auth.Service
	hasher *auth.Hasher
	now    func() time.Time
}

// New builds the service.
func New(db *database.DB, auditLog *audit.Logger, authSvc *auth.Service, hasher *auth.Hasher) *Service {
	return &Service{db: db, audit: auditLog, auth: authSvc, hasher: hasher, now: time.Now}
}

// NormalizeEmail lower-cases and trims an address and checks its shape.
func NormalizeEmail(raw string) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if len(email) < 3 || len(email) > 254 || strings.ContainsAny(email, " \t\r\n<>\",;") {
		return email, false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return email, false
	}
	at := strings.LastIndexByte(email, '@')
	return email, at > 0 && at < len(email)-1 && strings.Contains(email[at:], ".")
}

func checkDisplayName(f apperr.Fields, name string) {
	n := utf8.RuneCountInString(name)
	f.Check(n >= 1, "displayName", "Enter the person's name.")
	f.Check(n <= 200, "displayName", "Use at most 200 characters.")
	f.Check(!strings.ContainsAny(name, "\x00\r\n\t"), "displayName", "Names cannot contain line breaks or control characters.")
}

// visibleTo reports whether the caller may see this assignment.
func visibleTo(c access.Caller, a rbac.Assignment) bool {
	if a.Kind() == rbac.ScopeGlobal {
		return c.CanGlobal(rbac.PermUserView)
	}
	return c.Can(rbac.PermUserView, resourceOf(a))
}

// manageable reports whether the caller may change the target account.
func manageable(c access.Caller, target []rbac.Assignment) bool {
	if c.IsSystem() || c.Principal.IsSuperAdmin() {
		return true
	}
	if len(target) == 0 {
		return false
	}
	for _, a := range target {
		if !c.Principal.CanAssign(a) {
			return false
		}
	}
	return true
}

func (s *Service) loadAssignments(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) (map[uuid.UUID][]Assignment, error) {
	out := map[uuid.UUID][]Assignment{}
	if len(ids) == 0 {
		return out, nil
	}
	// Organization and site names come through RLS: names outside the
	// caller's scope are not revealed (those assignments are hidden anyway).
	rows, err := tx.Query(ctx, `SELECT ra.user_id, ra.role, ra.organization_id, coalesce(o.name, ''), ra.site_id, coalesce(s.name, '')
		FROM role_assignments ra
		LEFT JOIN organizations o ON o.id = ra.organization_id
		LEFT JOIN sites s ON s.id = ra.site_id
		WHERE ra.user_id = ANY($1)
		ORDER BY ra.user_id, ra.role, o.name NULLS FIRST, s.name NULLS FIRST`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uid uuid.UUID
		var a Assignment
		var role string
		if err := rows.Scan(&uid, &role, &a.OrganizationID, &a.OrganizationName, &a.SiteID, &a.SiteName); err != nil {
			return nil, err
		}
		a.Role = rbac.Role(role)
		out[uid] = append(out[uid], a)
	}
	return out, rows.Err()
}

func (s *Service) decorate(c access.Caller, u *User, assignments []Assignment) {
	u.Assignments = []Assignment{}
	u.all = nil
	for _, a := range assignments {
		ra := a.rbac()
		u.all = append(u.all, ra)
		if visibleTo(c, ra) {
			u.Assignments = append(u.Assignments, a)
		} else {
			u.HiddenAssignments++
		}
	}
	u.IsSelf = !c.IsSystem() && c.Principal != nil && c.Principal.UserID == u.ID
	u.CanManage = !u.IsSelf && manageable(c, u.all)
}

const userColumns = `u.id, u.email, u.display_name, u.status, u.totp_enabled_at IS NOT NULL, u.password_hash IS NOT NULL,
	coalesce(u.locked_until > now(), false), u.last_login_at, u.created_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Status, &u.MFAEnabled, &u.PasswordSet, &u.Locked, &u.LastLoginAt, &u.CreatedAt)
	return u, err
}

// visibilityClause restricts users to those holding a role the caller can
// see. $1 is the caller's id, $2 organizations and $3 sites with user.view.
const visibilityClause = `($4 OR u.id = $1 OR EXISTS (
	SELECT 1 FROM role_assignments ra WHERE ra.user_id = u.id
	AND (ra.organization_id = ANY($2) OR ra.site_id = ANY($3))))`

func visibilityArgs(c access.Caller) []any {
	if c.IsSystem() {
		return []any{uuid.Nil, []uuid.UUID{}, []uuid.UUID{}, true}
	}
	sc := c.Principal.Scope(rbac.PermUserView)
	orgs, sites := sc.Orgs, sc.Sites
	if orgs == nil {
		orgs = []uuid.UUID{}
	}
	if sites == nil {
		sites = []uuid.UUID{}
	}
	return []any{c.Principal.UserID, orgs, sites, sc.All}
}

// List returns a page of users visible to the caller, ordered by e-mail.
func (s *Service) List(ctx context.Context, c access.Caller, q ListQuery) ([]User, string, error) {
	if !c.IsSystem() && c.Principal.Scope(rbac.PermUserView).Empty() {
		return nil, "", apperr.Forbidden()
	}
	if q.Limit <= 0 || q.Limit > 200 {
		q.Limit = 100
	}
	after := ""
	if q.After != "" {
		b, err := base64.RawURLEncoding.DecodeString(q.After)
		if err != nil {
			return nil, "", apperr.Invalid("after", "is not a valid cursor")
		}
		after = string(b)
	}
	args := visibilityArgs(c)
	args = append(args, strings.ToLower(strings.TrimSpace(q.Search)), after, q.Limit+1, nullUUID(q.OrganizationID))
	var out []User
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+userColumns+` FROM users u
			WHERE `+visibilityClause+`
			  AND ($5 = '' OR strpos(u.email, $5) > 0 OR strpos(lower(u.display_name), $5) > 0)
			  AND u.email > $6
			  AND ($8::uuid IS NULL OR EXISTS (SELECT 1 FROM role_assignments rf WHERE rf.user_id = u.id AND rf.organization_id = $8))
			ORDER BY u.email LIMIT $7`, args...)
		if err != nil {
			return err
		}
		ids := []uuid.UUID{}
		for rows.Next() {
			u, err := scanUser(rows)
			if err != nil {
				rows.Close()
				return err
			}
			out = append(out, u)
			ids = append(ids, u.ID)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		as, err := s.loadAssignments(ctx, tx, ids)
		if err != nil {
			return err
		}
		for i := range out {
			s.decorate(c, &out[i], as[out[i].ID])
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > q.Limit {
		out = out[:q.Limit]
		next = base64.RawURLEncoding.EncodeToString([]byte(out[len(out)-1].Email))
	}
	if out == nil {
		out = []User{}
	}
	return out, next, nil
}

// Get returns one user visible to the caller.
func (s *Service) Get(ctx context.Context, c access.Caller, id uuid.UUID) (*User, error) {
	var u User
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return s.getTx(ctx, tx, c, id, &u)
	})
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Service) getTx(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID, u *User) error {
	args := append(visibilityArgs(c), id)
	got, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users u WHERE `+visibilityClause+` AND u.id = $5`, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return apperr.NotFound()
	}
	if err != nil {
		return err
	}
	as, err := s.loadAssignments(ctx, tx, []uuid.UUID{id})
	if err != nil {
		return err
	}
	*u = got
	s.decorate(c, u, as[id])
	return nil
}

// loadForChange fetches the target inside a write transaction, takes the
// user-administration lock, and checks the caller may change it.
func (s *Service) loadForChange(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID) (*User, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockUserAdmin)); err != nil {
		return nil, err
	}
	var u User
	if err := s.getTx(ctx, tx, c, id, &u); err != nil {
		return nil, err
	}
	if u.IsSelf {
		return nil, apperr.Conflict("self_change", "You cannot change your own access. Ask another administrator.")
	}
	if !u.CanManage {
		return nil, apperr.Forbidden()
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, id); err != nil {
		return nil, err
	}
	return &u, nil
}

func hasSuperAdmin(as []rbac.Assignment) bool {
	return slices.ContainsFunc(as, func(a rbac.Assignment) bool { return a.Role == rbac.RoleSuperAdmin })
}

// ensureAnotherSuperAdmin fails when removing the target's super
// administrator access would leave none.
func ensureAnotherSuperAdmin(ctx context.Context, tx pgx.Tx, target uuid.UUID) error {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM users u WHERE u.status = 'active' AND u.id <> $1
		AND EXISTS (SELECT 1 FROM role_assignments ra WHERE ra.user_id = u.id AND ra.role = 'super_admin')`, target).Scan(&n)
	if err != nil {
		return err
	}
	if n == 0 {
		return apperr.Conflict("last_super_admin", "This is the only active super administrator. Grant the role to someone else first.")
	}
	return nil
}

// validateGrants checks a set of requested assignments. Every one must be
// grantable by the caller and duplicates are rejected.
func validateGrants(c access.Caller, in []Assignment) ([]rbac.Assignment, error) {
	out := make([]rbac.Assignment, 0, len(in))
	seen := map[rbac.Assignment]bool{}
	for i, a := range in {
		ra := a.rbac()
		field := fmt.Sprintf("assignments.%d", i)
		if err := ra.Validate(); err != nil {
			return nil, apperr.Invalid(field, "This role cannot be granted at that level.")
		}
		if seen[ra] {
			return nil, apperr.Invalid(field, "This role is listed twice.")
		}
		seen[ra] = true
		if !c.IsSystem() && !c.Principal.CanAssign(ra) {
			return nil, apperr.Invalid(field, "You cannot grant this role here.")
		}
		out = append(out, ra)
	}
	return out, nil
}

func insertAssignments(ctx context.Context, tx pgx.Tx, userID uuid.UUID, createdBy uuid.UUID, as []rbac.Assignment) error {
	for _, a := range as {
		_, err := tx.Exec(ctx, `INSERT INTO role_assignments (user_id, role, organization_id, site_id, created_by) VALUES ($1, $2, $3, $4, $5)`,
			userID, string(a.Role), nullUUID(a.OrganizationID), nullUUID(a.SiteID), nullUUID(createdBy))
		if database.IsForeignKeyViolation(err) {
			return apperr.Invalid("assignments", "An organization or site in this list no longer exists, or the site is not in that organization.")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func describe(as []rbac.Assignment) []map[string]any {
	out := make([]map[string]any, 0, len(as))
	for _, a := range as {
		m := map[string]any{"role": string(a.Role)}
		if a.OrganizationID != uuid.Nil {
			m["organizationId"] = a.OrganizationID.String()
		}
		if a.SiteID != uuid.Nil {
			m["siteId"] = a.SiteID.String()
		}
		out = append(out, m)
	}
	return out
}

// auditOrg picks the organization an event about this user belongs to, so
// organization administrators see it in their audit log.
func auditOrg(as []rbac.Assignment) (org, site uuid.UUID) {
	if len(as) == 1 {
		return as[0].OrganizationID, as[0].SiteID
	}
	var o uuid.UUID
	for _, a := range as {
		if o != uuid.Nil && a.OrganizationID != o {
			return uuid.Nil, uuid.Nil
		}
		o = a.OrganizationID
	}
	return o, uuid.Nil
}

func (s *Service) callerID(c access.Caller) uuid.UUID {
	if c.Principal == nil {
		return uuid.Nil
	}
	return c.Principal.UserID
}

// Invite creates an account without a password and produces the link the
// person uses to choose one.
func (s *Service) Invite(ctx context.Context, c access.Caller, in InviteInput, meta auth.RequestMeta) (*InviteResult, error) {
	email, ok := NormalizeEmail(in.Email)
	name := strings.TrimSpace(in.DisplayName)
	f := apperr.Fields{}
	f.Check(ok, "email", "Enter a valid email address.")
	checkDisplayName(f, name)
	f.Check(len(in.Assignments) > 0, "assignments", "Grant at least one role.")
	f.Check(len(in.Assignments) <= 100, "assignments", "Grant at most 100 roles at once.")
	if err := f.Err(); err != nil {
		return nil, err
	}
	grants, err := validateGrants(c, in.Assignments)
	if err != nil {
		return nil, err
	}
	var id uuid.UUID
	var link string
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id`, email, name).Scan(&id)
		if database.IsUniqueViolation(err) {
			return apperr.Invalid("email", "An account with this email address already exists.")
		}
		if err != nil {
			return err
		}
		if err := insertAssignments(ctx, tx, id, s.callerID(c), grants); err != nil {
			return err
		}
		if link, err = s.auth.IssueInviteToken(ctx, tx, id, meta); err != nil {
			return err
		}
		org, site := auditOrg(grants)
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "user.invite", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "user", TargetID: id.String(),
			Details: map[string]any{"email": email, "assignments": describe(grants)}})
	})
	if err != nil {
		return nil, err
	}
	res := &InviteResult{}
	if m := s.auth.Mailer(); m != nil {
		body := "You have been invited to EasyRMM by " + c.Actor.Label + ".\n\n" +
			"Open this link within " + auth.InviteTTL.String() + " to choose your password and set up two-factor sign-in:\n\n" +
			link + "\n\nIf you were not expecting this, you can ignore this message.\n"
		if err := m.Send(context.WithoutCancel(ctx), email, "You have been invited to EasyRMM", body); err == nil {
			res.Emailed = true
		}
	}
	if !res.Emailed {
		res.Link = link
	}
	if res.User, err = s.Get(ctx, c, id); err != nil {
		return nil, err
	}
	return res, nil
}

// UpdateProfile changes a user's display name.
func (s *Service) UpdateProfile(ctx context.Context, c access.Caller, id uuid.UUID, displayName string) (*User, error) {
	name := strings.TrimSpace(displayName)
	f := apperr.Fields{}
	checkDisplayName(f, name)
	if err := f.Err(); err != nil {
		return nil, err
	}
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		u, err := s.loadForChange(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET display_name = $2 WHERE id = $1`, id, name); err != nil {
			return err
		}
		org, site := auditOrg(u.all)
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "user.update", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "user", TargetID: id.String(),
			Details: map[string]any{"displayName": name, "previousDisplayName": u.DisplayName}})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, c, id)
}

// SetAssignments replaces the roles the caller controls. Roles the target
// holds outside the caller's authority are left untouched.
func (s *Service) SetAssignments(ctx context.Context, c access.Caller, id uuid.UUID, in []Assignment) (*User, error) {
	if len(in) > 100 {
		return nil, apperr.Invalid("assignments", "Grant at most 100 roles at once.")
	}
	grants, err := validateGrants(c, in)
	if err != nil {
		return nil, err
	}
	var u User
	var kept int
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockUserAdmin)); err != nil {
			return err
		}
		if err := s.getTx(ctx, tx, c, id, &u); err != nil {
			return err
		}
		if u.IsSelf {
			return apperr.Conflict("self_change", "You cannot change your own access. Ask another administrator.")
		}
		// Unlike other changes, granting roles does not require authority
		// over every existing role: an organization administrator may add a
		// user from another customer to their own organization.
		var keep, remove []rbac.Assignment
		for _, a := range u.all {
			if c.IsSystem() || c.Principal.CanAssign(a) {
				remove = append(remove, a)
			} else {
				keep = append(keep, a)
			}
		}
		kept = len(keep)
		if len(keep)+len(grants) == 0 {
			return apperr.Invalid("assignments", "Grant at least one role. To remove all access, disable the account.")
		}
		if hasSuperAdmin(u.all) && !hasSuperAdmin(grants) && !hasSuperAdmin(keep) && u.Status == "active" {
			if err := ensureAnotherSuperAdmin(ctx, tx, id); err != nil {
				return err
			}
		}
		for _, a := range remove {
			_, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE user_id = $1 AND role = $2
				AND organization_id IS NOT DISTINCT FROM $3 AND site_id IS NOT DISTINCT FROM $4`,
				id, string(a.Role), nullUUID(a.OrganizationID), nullUUID(a.SiteID))
			if err != nil {
				return err
			}
		}
		if err := insertAssignments(ctx, tx, id, s.callerID(c), grants); err != nil {
			return err
		}
		org, site := auditOrg(append(slices.Clone(remove), grants...))
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "user.roles_change", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "user", TargetID: id.String(),
			Details: map[string]any{"email": u.Email, "removed": describe(remove), "granted": describe(grants)}})
	})
	if err != nil {
		return nil, err
	}
	after, err := s.Get(ctx, c, id)
	if errors.Is(err, apperr.ErrNotFound) && len(grants) == 0 {
		// The caller removed every role they can see: the change succeeded
		// but the user is now outside their view. Report that, rather than
		// a not-found error for a change that was made.
		u.Assignments, u.HiddenAssignments, u.CanManage = []Assignment{}, kept, false
		return &u, nil
	}
	return after, err
}

// SetStatus enables or disables an account. Disabling signs the user out
// everywhere.
func (s *Service) SetStatus(ctx context.Context, c access.Caller, id uuid.UUID, status string) (*User, error) {
	if status != "active" && status != "disabled" {
		return nil, apperr.Invalid("status", "Status must be active or disabled.")
	}
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		u, err := s.loadForChange(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if u.Status == status {
			return nil
		}
		if status == "disabled" {
			if hasSuperAdmin(u.all) {
				if err := ensureAnotherSuperAdmin(ctx, tx, id); err != nil {
					return err
				}
			}
			if err := auth.RevokeAllSessions(ctx, tx, id, uuid.Nil, "account_disabled"); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET status = $2, failed_logins = 0, locked_until = NULL WHERE id = $1`, id, status); err != nil {
			return err
		}
		action := "user.enable"
		if status == "disabled" {
			action = "user.disable"
		}
		org, site := auditOrg(u.all)
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: action, Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "user", TargetID: id.String(), Details: map[string]any{"email": u.Email}})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, c, id)
}

// Unlock clears a sign-in lockout.
func (s *Service) Unlock(ctx context.Context, c access.Caller, id uuid.UUID) (*User, error) {
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		u, err := s.loadForChange(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1`, id); err != nil {
			return err
		}
		org, site := auditOrg(u.all)
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "user.unlock", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "user", TargetID: id.String(), Details: map[string]any{"email": u.Email}})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, c, id)
}

// ResetMFA removes a user's second factor and recovery codes so they can
// enroll again at their next sign-in, and signs them out everywhere.
func (s *Service) ResetMFA(ctx context.Context, c access.Caller, id uuid.UUID) (*User, error) {
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		u, err := s.loadForChange(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET totp_secret_sealed = NULL, totp_enabled_at = NULL, totp_last_step = NULL WHERE id = $1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM user_recovery_codes WHERE user_id = $1`, id); err != nil {
			return err
		}
		if err := auth.RevokeAllSessions(ctx, tx, id, uuid.Nil, "mfa_reset"); err != nil {
			return err
		}
		org, site := auditOrg(u.all)
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "user.mfa_reset", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "user", TargetID: id.String(), Details: map[string]any{"email": u.Email}})
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, c, id)
}

// IssuePasswordLink creates a password reset link (or a fresh invitation
// for users who never set a password). It is e-mailed when mail is
// configured; otherwise it is returned for the administrator to deliver.
func (s *Service) IssuePasswordLink(ctx context.Context, c access.Caller, id uuid.UUID, meta auth.RequestMeta) (*InviteResult, error) {
	var link, email string
	var invite bool
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		u, err := s.loadForChange(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if u.Status != "active" {
			return apperr.Conflict("user_disabled", "Enable this account before sending it a password link.")
		}
		email, invite = u.Email, !u.PasswordSet
		if invite {
			link, err = s.auth.IssueInviteToken(ctx, tx, id, meta)
		} else {
			link, err = s.auth.IssueResetToken(ctx, tx, id, meta)
		}
		if err != nil {
			return err
		}
		org, site := auditOrg(u.all)
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "user.password_link", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "user", TargetID: id.String(),
			Details: map[string]any{"email": u.Email, "invite": invite}})
	})
	if err != nil {
		return nil, err
	}
	res := &InviteResult{}
	if m := s.auth.Mailer(); m != nil {
		subject, body := "Reset your EasyRMM password", "An administrator ("+c.Actor.Label+") sent you a link to choose a new EasyRMM password:\n\n"+link+
			"\n\nIt expires soon. If you were not expecting this, contact your administrator.\n"
		if invite {
			subject, body = "You have been invited to EasyRMM", "You have been invited to EasyRMM by "+c.Actor.Label+".\n\n"+
				"Open this link within "+auth.InviteTTL.String()+" to choose your password:\n\n"+link+"\n"
		}
		if err := m.Send(context.WithoutCancel(ctx), email, subject, body); err == nil {
			res.Emailed = true
		}
	}
	if !res.Emailed {
		res.Link = link
	}
	if res.User, err = s.Get(ctx, c, id); err != nil {
		return nil, err
	}
	return res, nil
}

// Delete removes an account. Its audit history remains.
func (s *Service) Delete(ctx context.Context, c access.Caller, id uuid.UUID) error {
	return s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		u, err := s.loadForChange(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if hasSuperAdmin(u.all) && u.Status == "active" {
			if err := ensureAnotherSuperAdmin(ctx, tx, id); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
			return err
		}
		org, site := auditOrg(u.all)
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "user.delete", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "user", TargetID: id.String(), Details: map[string]any{"email": u.Email}})
	})
}

// UpdateOwnProfile lets a signed-in user change their display name.
func (s *Service) UpdateOwnProfile(ctx context.Context, actor audit.Actor, userID uuid.UUID, displayName string) error {
	name := strings.TrimSpace(displayName)
	f := apperr.Fields{}
	checkDisplayName(f, name)
	if err := f.Err(); err != nil {
		return err
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE users SET display_name = $2 WHERE id = $1`, userID, name); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "user.update", Outcome: audit.Success,
			TargetType: "user", TargetID: userID.String(), Details: map[string]any{"displayName": name, "self": true}})
	})
}

// ErrSetupDone is returned when first-run setup has already completed.
var ErrSetupDone = apperr.Conflict("setup_complete", "This server is already set up. Sign in instead.")

// SetupInput creates the first administrator.
type SetupInput struct {
	Email            string `json:"email"`
	DisplayName      string `json:"displayName"`
	Password         string `json:"password"`
	OrganizationName string `json:"organizationName"`
}

// NeedsSetup reports whether no account exists yet.
func (s *Service) NeedsSetup(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&exists)
	})
	return !exists, err
}

// Bootstrap creates the first super administrator (and optionally the
// first organization). It succeeds only while no account exists.
func (s *Service) Bootstrap(ctx context.Context, in SetupInput, meta auth.RequestMeta) (uuid.UUID, error) {
	email, ok := NormalizeEmail(in.Email)
	name := strings.TrimSpace(in.DisplayName)
	orgName := strings.TrimSpace(in.OrganizationName)
	f := apperr.Fields{}
	f.Check(ok, "email", "Enter a valid email address.")
	checkDisplayName(f, name)
	f.Check(utf8.RuneCountInString(orgName) <= 200, "organizationName", "Use at most 200 characters.")
	if err := auth.ValidatePassword(in.Password, email, name, strings.Split(email, "@")[0]); err != nil {
		f.Add("password", auth.PasswordAdvice(err))
	}
	if err := f.Err(); err != nil {
		return uuid.Nil, err
	}
	hash, err := s.hasher.Hash(ctx, in.Password)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockUserAdmin)); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrSetupDone
		}
		if err := tx.QueryRow(ctx, `INSERT INTO users (email, display_name, password_hash, password_changed_at) VALUES ($1, $2, $3, now()) RETURNING id`,
			email, name, hash).Scan(&id); err != nil {
			return err
		}
		if err := insertAssignments(ctx, tx, id, uuid.Nil, []rbac.Assignment{{Role: rbac.RoleSuperAdmin}}); err != nil {
			return err
		}
		actor := audit.Actor{Type: audit.ActorUser, ID: id, Label: email, SourceIP: meta.IP, UserAgent: meta.UserAgent}
		if err := s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "setup.complete", Outcome: audit.Success,
			TargetType: "user", TargetID: id.String(), Details: map[string]any{"email": email}}); err != nil {
			return err
		}
		if orgName == "" {
			return nil
		}
		var orgID uuid.UUID
		if err := tx.QueryRow(ctx, `INSERT INTO organizations (name) VALUES ($1) RETURNING id`, orgName).Scan(&orgID); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "organization.create", Outcome: audit.Success,
			OrganizationID: orgID, TargetType: "organization", TargetID: orgID.String(), Details: map[string]any{"name": orgName}})
	})
	return id, err
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
