package remote

import (
	"sort"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
)

// The reconciliation is split into pure planning functions (tested without
// MeshCentral) and an apply step that performs the plan.

type meshPlan struct {
	create []siteInfo           // sites without a group
	adopt  map[uuid.UUID]string // site → existing marked group to record
	rename []meshRename         // groups whose name or description drifted
	remove []string             // marked groups whose site no longer exists
	mesh   map[uuid.UUID]string // site → group, for groups that exist now
	known  map[string]uuid.UUID // group → site
	stale  []uuid.UUID          // mapping rows whose group no longer exists
}

type meshRename struct {
	MeshID, Name, Desc string
}

// planMeshes compares sites with MeshCentral's groups. mapping is the
// recorded site → group table.
func planMeshes(sites []siteInfo, meshes []meshcentral.Mesh, mapping map[uuid.UUID]string) meshPlan {
	p := meshPlan{adopt: map[uuid.UUID]string{}, mesh: map[uuid.UUID]string{}, known: map[string]uuid.UUID{}}
	byID := map[string]meshcentral.Mesh{}
	marked := map[uuid.UUID][]meshcentral.Mesh{}
	for _, m := range meshes {
		byID[m.ID] = m
		if site, ok := markedSite(m); ok {
			marked[site] = append(marked[site], m)
		}
	}
	claimed := map[string]bool{}
	for _, s := range sites {
		var m meshcentral.Mesh
		var found bool
		if id, ok := mapping[s.ID]; ok {
			m, found = byID[id]
			if !found {
				p.stale = append(p.stale, s.ID)
			}
		}
		if !found {
			// Adopt a group EasyRMM created earlier but did not record (for
			// example a create whose reply was lost). Oldest id first, so
			// the choice is stable.
			cands := marked[s.ID]
			sort.Slice(cands, func(i, j int) bool { return cands[i].ID < cands[j].ID })
			if len(cands) > 0 {
				m, found = cands[0], true
				p.adopt[s.ID] = m.ID
			}
		}
		if !found {
			p.create = append(p.create, s)
			continue
		}
		claimed[m.ID] = true
		p.mesh[s.ID] = m.ID
		p.known[m.ID] = s.ID
		if m.Name != s.meshName() || m.Description != s.meshDesc() {
			p.rename = append(p.rename, meshRename{MeshID: m.ID, Name: s.meshName(), Desc: s.meshDesc()})
		}
	}
	for _, m := range meshes {
		// A marked group that no site claims: its site was deleted, or it
		// is a duplicate of the group the site uses.
		if _, ok := markedSite(m); ok && !claimed[m.ID] {
			p.remove = append(p.remove, m.ID)
		}
	}
	sort.Strings(p.remove)
	return p
}

type userPlan struct {
	add    []userInfo
	edit   []userInfo
	remove []string // MeshCentral user ids
}

// planUsers compares the users who should have a MeshCentral account with
// the accounts that exist. Accounts not named like EasyRMM's are left alone,
// as is the service account.
func planUsers(want []userInfo, have []meshcentral.User) userPlan {
	var p userPlan
	existing := map[uuid.UUID]meshcentral.User{}
	for _, u := range have {
		if id, ok := userOfAccount(u.ID); ok {
			existing[id] = u
		}
	}
	wanted := map[uuid.UUID]bool{}
	for _, u := range want {
		wanted[u.ID] = true
		cur, ok := existing[u.ID]
		switch {
		case !ok:
			p.add = append(p.add, u)
		case cur.RealName != realName(u) || cur.SiteAdmin != meshcentral.TechnicianSiteRights:
			p.edit = append(p.edit, u)
		}
	}
	for id, u := range existing {
		if !wanted[id] {
			p.remove = append(p.remove, u.ID)
		}
	}
	sort.Strings(p.remove)
	return p
}

// realName is what MeshCentral shows end users in consent and notification
// prompts.
func realName(u userInfo) string { return truncateRunes(u.Name, 256) }

type rightChange struct {
	MeshID, UserID string
	Rights         uint32 // 0 removes the link
}

// planRights compares each EasyRMM account's rights on each EasyRMM group
// with what it should hold. Links of other accounts (the service account,
// anything added by hand) are not touched.
func planRights(want []userInfo, meshes []meshcentral.Mesh, known map[string]uuid.UUID) []rightChange {
	var out []rightChange
	access := map[uuid.UUID]userInfo{}
	for _, u := range want {
		access[u.ID] = u
	}
	sort.Slice(meshes, func(i, j int) bool { return meshes[i].ID < meshes[j].ID })
	for _, m := range meshes {
		site, ok := known[m.ID]
		if !ok {
			continue
		}
		seen := map[uuid.UUID]bool{}
		var linked []string
		for uid := range m.Links {
			linked = append(linked, uid)
		}
		sort.Strings(linked)
		for _, uid := range linked {
			id, ok := userOfAccount(uid)
			if !ok {
				continue
			}
			seen[id] = true
			wantRights := access[id].Access[site].Rights()
			if wantRights == 0 {
				out = append(out, rightChange{MeshID: m.ID, UserID: uid, Rights: 0})
			} else if m.Links[uid].Rights != wantRights {
				out = append(out, rightChange{MeshID: m.ID, UserID: uid, Rights: wantRights})
			}
		}
		for _, u := range want {
			if r := u.Access[site].Rights(); r != 0 && !seen[u.ID] {
				out = append(out, rightChange{MeshID: m.ID, UserID: accountID(u.ID), Rights: r})
			}
		}
	}
	return out
}
