package remote

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// What EasyRMM wants MeshCentral to look like.
type desired struct {
	sites []siteInfo
	users []userInfo
}

type siteInfo struct {
	ID, OrgID uuid.UUID
	OrgName   string
	Name      string
}

// meshName is the device group name shown in MeshCentral (and to end users
// in some agent prompts): "Organization / Site", within MeshCentral's limit.
func (s siteInfo) meshName() string {
	return truncateRunes(s.OrgName+" / "+s.Name, 128)
}

// meshDesc marks the group as EasyRMM's and names its site.
func (s siteInfo) meshDesc() string {
	return "EasyRMM site " + s.ID.String() + ". Managed by EasyRMM: changes made in MeshCentral are overwritten."
}

var siteMarker = regexp.MustCompile(`^EasyRMM site ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.`)

// markedSite returns the site a MeshCentral group belongs to, if EasyRMM
// created it.
func markedSite(m meshcentral.Mesh) (uuid.UUID, bool) {
	sm := siteMarker.FindStringSubmatch(m.Description)
	if sm == nil {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(sm[1])
	return id, err == nil
}

type userInfo struct {
	ID     uuid.UUID
	Name   string
	Access map[uuid.UUID]meshcentral.Access // by site; only sites with some access
}

// accountName is the MeshCentral account behind an EasyRMM user.
func accountName(id uuid.UUID) string { return "easyrmm-" + id.String() }

func accountID(id uuid.UUID) string { return meshcentral.UserID(accountName(id)) }

// userOfAccount returns the EasyRMM user a MeshCentral account stands for.
func userOfAccount(meshUserID string) (uuid.UUID, bool) {
	name, ok := strings.CutPrefix(meshUserID, "user//easyrmm-")
	if !ok {
		return uuid.Nil, false
	}
	id, err := uuid.Parse(name)
	return id, err == nil && strings.ToLower(id.String()) == name
}

// accessFor converts a principal's permissions at a site into MeshCentral
// access.
func accessFor(p *rbac.Principal, orgID, siteID uuid.UUID) meshcentral.Access {
	r := rbac.Site(orgID, siteID)
	return meshcentral.Access{
		Desktop:  p.Can(rbac.PermRemoteDesktop, r),
		Terminal: p.Can(rbac.PermTerminal, r),
		Files:    p.Can(rbac.PermFiles, r),
	}
}

// loadDesired reads every site and every active user with their roles.
func loadDesired(ctx context.Context, db *database.DB) (*desired, error) {
	d := &desired{}
	assignments := map[uuid.UUID][]rbac.Assignment{}
	names := map[uuid.UUID]string{}
	err := db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT s.id, s.organization_id, o.name, s.name
			FROM sites s JOIN organizations o ON o.id = s.organization_id ORDER BY s.id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var s siteInfo
			if err := rows.Scan(&s.ID, &s.OrgID, &s.OrgName, &s.Name); err != nil {
				rows.Close()
				return err
			}
			d.sites = append(d.sites, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT u.id, u.display_name, r.role, r.organization_id, r.site_id
			FROM users u JOIN role_assignments r ON r.user_id = u.id
			WHERE u.status = 'active'`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var name, role string
			var org, site *uuid.UUID
			if err := rows.Scan(&id, &name, &role, &org, &site); err != nil {
				return err
			}
			a := rbac.Assignment{Role: rbac.Role(role)}
			if org != nil {
				a.OrganizationID = *org
			}
			if site != nil {
				a.SiteID = *site
			}
			names[id] = name
			assignments[id] = append(assignments[id], a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("loading users and sites: %w", err)
	}
	for id, as := range assignments {
		p, err := rbac.NewPrincipal(id, as)
		if err != nil {
			return nil, fmt.Errorf("user %s: %w", id, err)
		}
		u := userInfo{ID: id, Name: names[id], Access: map[uuid.UUID]meshcentral.Access{}}
		for _, s := range d.sites {
			if a := accessFor(p, s.OrgID, s.ID); a.Any() {
				u.Access[s.ID] = a
			}
		}
		if len(u.Access) > 0 {
			d.users = append(d.users, u)
		}
	}
	sort.Slice(d.users, func(i, j int) bool { return d.users[i].ID.String() < d.users[j].ID.String() })
	return d, nil
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// platformOf maps a MeshAgent architecture number to a platform.
func platformOf(agentType int) string {
	switch agentType {
	case 1, 2, 3, 4, 21, 22, 42, 43, 10003, 10004:
		return "windows"
	case 16, 29, 10005:
		return "macos"
	case 5, 6, 7, 8, 9, 10, 13, 15, 18, 19, 20, 24, 25, 26, 27, 28, 32, 33, 35, 36, 40, 41, 45:
		return "linux"
	}
	return "other"
}
