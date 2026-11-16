package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devices"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Script levels.
const (
	LevelShared       = "shared"
	LevelOrganization = "organization"
	LevelSite         = "site"
)

// Script is a library script.
type Script struct {
	ID               uuid.UUID  `json:"id"`
	Level            string     `json:"level"`
	OrganizationID   *uuid.UUID `json:"organizationId"`
	OrganizationName string     `json:"organizationName,omitempty"`
	SiteID           *uuid.UUID `json:"siteId"`
	SiteName         string     `json:"siteName,omitempty"`
	Name             string     `json:"name"`
	Description      string     `json:"description"`
	Shell            string     `json:"shell"`
	// Body is filled in by Get only.
	Body           string    `json:"body,omitempty"`
	SHA256         string    `json:"sha256"`
	Size           int       `json:"size"`
	TimeoutSeconds int       `json:"timeoutSeconds"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	// What the caller may do with it.
	CanEdit bool `json:"canEdit"`
	CanRun  bool `json:"canRun"`
}

// resource is where the script lives, for permission checks.
func (sc *Script) level() (org, site uuid.UUID) {
	if sc.OrganizationID != nil {
		org = *sc.OrganizationID
	}
	if sc.SiteID != nil {
		site = *sc.SiteID
	}
	return org, site
}

// canAt reports whether the caller holds perm at the script's level or,
// for reading and running, anywhere below it.
func canAt(c access.Caller, perm rbac.Permission, org, site uuid.UUID, below bool) bool {
	switch {
	case org == uuid.Nil && below:
		return c.CanAnywhere(perm)
	case org == uuid.Nil:
		return c.CanGlobal(perm)
	case site != uuid.Nil:
		return c.Can(perm, rbac.Site(org, site))
	case below:
		return c.CanInOrg(perm, org)
	default:
		return c.Can(perm, rbac.Org(org))
	}
}

func (s *Service) decorateScript(c access.Caller, sc *Script) {
	org, site := sc.level()
	sc.CanEdit = canAt(c, rbac.PermScriptManage, org, site, false)
	sc.CanRun = canAt(c, rbac.PermScriptRun, org, site, true)
}

// covers reports whether a script at this level (org, site) may run on a
// device of devOrg and devSite.
func covers(org, site, devOrg, devSite uuid.UUID) bool {
	return org == uuid.Nil || (org == devOrg && (site == uuid.Nil || site == devSite))
}

const scriptColumns = `sc.id, sc.organization_id, coalesce(o.name, ''), sc.site_id, coalesce(si.name, ''),
	sc.name, sc.description, sc.shell, encode(sha256(convert_to(sc.body, 'UTF8')), 'hex'), octet_length(sc.body),
	sc.timeout_seconds, sc.created_at, sc.updated_at`

const scriptFrom = ` FROM scripts sc
	LEFT JOIN organizations o ON o.id = sc.organization_id
	LEFT JOIN sites si ON si.id = sc.site_id`

func scanScript(row pgx.Row, extra ...any) (*Script, error) {
	var sc Script
	dst := append([]any{&sc.ID, &sc.OrganizationID, &sc.OrganizationName, &sc.SiteID, &sc.SiteName,
		&sc.Name, &sc.Description, &sc.Shell, &sc.SHA256, &sc.Size,
		&sc.TimeoutSeconds, &sc.CreatedAt, &sc.UpdatedAt}, extra...)
	if err := row.Scan(dst...); err != nil {
		return nil, err
	}
	switch {
	case sc.SiteID != nil:
		sc.Level = LevelSite
	case sc.OrganizationID != nil:
		sc.Level = LevelOrganization
	default:
		sc.Level = LevelShared
	}
	return &sc, nil
}

// ScriptQuery filters the script list.
type ScriptQuery struct {
	// OrganizationID lists an organization's scripts and its sites'.
	OrganizationID uuid.UUID
	// SiteID lists one site's scripts.
	SiteID uuid.UUID
	// Shared lists the shared library only.
	Shared bool
	// DeviceID lists the scripts that can run on a device.
	DeviceID uuid.UUID
	Search   string
}

// MaxScripts bounds the script list.
const MaxScripts = 2000

// ListScripts returns the scripts the caller can read, by name.
func (s *Service) ListScripts(ctx context.Context, c access.Caller, q ScriptQuery) ([]*Script, error) {
	var dev *devices.Device
	if q.DeviceID != uuid.Nil {
		d, err := devices.Lookup(ctx, s.db, c, q.DeviceID)
		if err != nil {
			return nil, err
		}
		dev = d
	}
	out := []*Script{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+scriptColumns+scriptFrom+`
			WHERE ($1::uuid IS NULL OR sc.organization_id = $1)
			  AND ($2::uuid IS NULL OR sc.site_id = $2)
			  AND (NOT $3 OR sc.organization_id IS NULL)
			  AND ($4 = '' OR strpos(lower(sc.name), lower($4)) > 0 OR strpos(lower(sc.description), lower($4)) > 0)
			ORDER BY lower(sc.name), sc.id LIMIT $5`,
			nullUUID(q.OrganizationID), nullUUID(q.SiteID), q.Shared, strings.TrimSpace(q.Search), MaxScripts)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			sc, err := scanScript(rows)
			if err != nil {
				return err
			}
			org, site := sc.level()
			if !canAt(c, rbac.PermScriptView, org, site, true) {
				continue
			}
			if dev != nil && !covers(org, site, dev.OrganizationID, dev.SiteID) {
				continue
			}
			s.decorateScript(c, sc)
			out = append(out, sc)
		}
		return rows.Err()
	})
	return out, err
}

// GetScript returns a script with its body.
func (s *Service) GetScript(ctx context.Context, c access.Caller, id uuid.UUID) (*Script, error) {
	var sc *Script
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		sc, err = s.getScript(ctx, tx, c, id, false)
		return err
	})
	return sc, err
}

// editable reads a script for a change: it must be readable (or the answer
// is not found) and writable by the caller (or forbidden), and it is locked.
// Row locks need the update policy too, so the check reads before it locks.
func (s *Service) editable(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID) (*Script, error) {
	cur, err := s.getScript(ctx, tx, c, id, false)
	if err != nil {
		return nil, err
	}
	if !cur.CanEdit {
		return nil, apperr.Forbidden()
	}
	cur, err = s.getScript(ctx, tx, c, id, true)
	if errors.Is(err, apperr.ErrNotFound) {
		return nil, apperr.Forbidden()
	}
	return cur, err
}

// getScript reads a script the caller may read, with its body.
func (s *Service) getScript(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID, lock bool) (*Script, error) {
	q := `SELECT ` + scriptColumns + `, sc.body` + scriptFrom + ` WHERE sc.id = $1`
	if lock {
		q += ` FOR UPDATE OF sc`
	}
	var body string
	sc, err := scanScript(tx.QueryRow(ctx, q, id), &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	org, site := sc.level()
	if !canAt(c, rbac.PermScriptView, org, site, true) {
		return nil, apperr.NotFound()
	}
	sc.Body = body
	s.decorateScript(c, sc)
	return sc, nil
}

// ScriptInput creates a script.
type ScriptInput struct {
	OrganizationID *uuid.UUID `json:"organizationId"`
	SiteID         *uuid.UUID `json:"siteId"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	Shell          string     `json:"shell"`
	Body           string     `json:"body"`
	TimeoutSeconds int        `json:"timeoutSeconds"`
}

// ScriptPatch changes a script; nil fields stay as they are. A script does
// not move between levels.
type ScriptPatch struct {
	Name           *string `json:"name"`
	Description    *string `json:"description"`
	Shell          *string `json:"shell"`
	Body           *string `json:"body"`
	TimeoutSeconds *int    `json:"timeoutSeconds"`
}

// normalizeBody stores line endings as LF.
func normalizeBody(b string) string {
	return strings.ReplaceAll(strings.ReplaceAll(b, "\r\n", "\n"), "\r", "\n")
}

func validateScript(f apperr.Fields, name, description, shell, body string, timeout int) {
	f.Check(name != "", "name", "Enter a name.")
	f.Check(utf8.RuneCountInString(name) <= MaxName, "name", "Use at most 200 characters.")
	f.Check(utf8.RuneCountInString(description) <= MaxDescription, "description", "Use at most 2,000 characters.")
	f.Check(agentproto.ValidShell(shell), "shell", "Choose bash, sh or python3.")
	switch {
	case strings.TrimSpace(body) == "":
		f.Add("body", "Enter the script.")
	case len(body) > MaxBody:
		f.Add("body", "Keep the script under 64 KiB.")
	case !utf8.ValidString(body) || strings.ContainsRune(body, 0):
		f.Add("body", "The script must be UTF-8 text without NUL characters.")
	}
	f.Check(timeout >= MinTimeout && timeout <= MaxTimeout, "timeoutSeconds", "Use 1 second to 4 hours.")
}

func bodyHash(body string) string {
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

// CreateScript adds a script at the level the input names.
func (s *Service) CreateScript(ctx context.Context, c access.Caller, in ScriptInput) (*Script, error) {
	var org, site uuid.UUID
	if in.OrganizationID != nil {
		org = *in.OrganizationID
	}
	if in.SiteID != nil {
		site = *in.SiteID
		if org == uuid.Nil {
			return nil, apperr.Invalid("organizationId", "A site's script needs its organization.")
		}
	}
	if !canAt(c, rbac.PermScriptManage, org, site, false) {
		return nil, apperr.Forbidden()
	}
	name, description := cleanText(in.Name, false), cleanText(in.Description, true)
	body := normalizeBody(in.Body)
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = DefaultTimeout
	}
	f := apperr.Fields{}
	validateScript(f, name, description, in.Shell, body, in.TimeoutSeconds)
	if err := f.Err(); err != nil {
		return nil, err
	}
	var id uuid.UUID
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `INSERT INTO scripts (organization_id, site_id, name, description, shell, body, timeout_seconds, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8) RETURNING id`,
			nullUUID(org), nullUUID(site), name, description, in.Shell, body, in.TimeoutSeconds, nullUUID(c.Actor.ID)).Scan(&id)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "script.create", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "script", TargetID: id.String(),
			Details: map[string]any{"name": name, "shell": in.Shell, "sha256": bodyHash(body), "timeoutSeconds": in.TimeoutSeconds},
		})
	})
	if err != nil {
		return nil, scriptWriteError(err)
	}
	return s.GetScript(ctx, c, id)
}

// UpdateScript changes a script.
func (s *Service) UpdateScript(ctx context.Context, c access.Caller, id uuid.UUID, p ScriptPatch) (*Script, error) {
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		cur, err := s.editable(ctx, tx, c, id)
		if err != nil {
			return err
		}
		name, description, shell, body, timeout := cur.Name, cur.Description, cur.Shell, cur.Body, cur.TimeoutSeconds
		if p.Name != nil {
			name = cleanText(*p.Name, false)
		}
		if p.Description != nil {
			description = cleanText(*p.Description, true)
		}
		if p.Shell != nil {
			shell = *p.Shell
		}
		if p.Body != nil {
			body = normalizeBody(*p.Body)
		}
		if p.TimeoutSeconds != nil {
			timeout = *p.TimeoutSeconds
		}
		f := apperr.Fields{}
		validateScript(f, name, description, shell, body, timeout)
		if err := f.Err(); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE scripts SET name = $2, description = $3, shell = $4, body = $5, timeout_seconds = $6, updated_by = $7
			WHERE id = $1`, id, name, description, shell, body, timeout, nullUUID(c.Actor.ID)); err != nil {
			return err
		}
		changes := map[string]any{}
		if name != cur.Name {
			changes["name"] = map[string]string{"from": cur.Name, "to": name}
		}
		if description != cur.Description {
			changes["description"] = true
		}
		if shell != cur.Shell {
			changes["shell"] = map[string]string{"from": cur.Shell, "to": shell}
		}
		if body != cur.Body {
			changes["sha256"] = map[string]string{"from": cur.SHA256, "to": bodyHash(body)}
		}
		if timeout != cur.TimeoutSeconds {
			changes["timeoutSeconds"] = map[string]int{"from": cur.TimeoutSeconds, "to": timeout}
		}
		if len(changes) == 0 {
			return nil
		}
		org, site := cur.level()
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "script.update", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "script", TargetID: id.String(),
			Details: map[string]any{"name": name, "changes": changes},
		})
	})
	if err != nil {
		return nil, scriptWriteError(err)
	}
	return s.GetScript(ctx, c, id)
}

// DeleteScript removes a script. Jobs that ran it keep their snapshot.
func (s *Service) DeleteScript(ctx context.Context, c access.Caller, id uuid.UUID) error {
	return s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		cur, err := s.editable(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scripts WHERE id = $1`, id); err != nil {
			return err
		}
		org, site := cur.level()
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "script.delete", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, TargetType: "script", TargetID: id.String(),
			Details: map[string]any{"name": cur.Name, "sha256": cur.SHA256},
		})
	})
}

func scriptWriteError(err error) error {
	switch {
	case database.IsUniqueViolation(err):
		return apperr.Invalid("name", "A script with this name already exists here.")
	case database.IsForeignKeyViolation(err):
		return apperr.Invalid("siteId", "That site is not in that organization.")
	case database.IsRLSViolation(err):
		return apperr.Forbidden()
	}
	return err
}

func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
