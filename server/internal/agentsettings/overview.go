package agentsettings

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The document states the console shows for a device (ADR-0058, slice 3).
const (
	// DocApplied: the agent reported applying the version last issued.
	DocApplied = "applied"
	// DocWaiting: the agent has not applied the version issued, and the
	// device is offline.
	DocWaiting = "waiting"
	// DocPending: issued, not applied yet, the device is online.
	DocPending = "pending"
	// DocNotApplied: three heartbeats with the report since the issue
	// without the version applied.
	DocNotApplied = "not_applied"
	// DocUnsupported: the agent does not take settings documents.
	DocUnsupported = "unsupported"
	// DocNone: the agent takes settings, and nothing has been issued yet.
	DocNone = "none"
)

// DocumentView is a device's settings delivery as the console shows it.
type DocumentView struct {
	State                string            `json:"state"`
	Version              int64             `json:"version"`
	AppliedVersion       int64             `json:"appliedVersion"`
	IssuedAt             *time.Time        `json:"issuedAt"`
	AppliedAt            *time.Time        `json:"appliedAt"`
	NotAppliedHeartbeats int               `json:"notAppliedHeartbeats"`
	Problems             map[string]string `json:"problems"`
}

// Describe judges a device's state; online is whether its agent is online.
func Describe(st State, online bool) DocumentView {
	v := DocumentView{
		State: DocNone, Version: st.DocVersion, AppliedVersion: st.AppliedVersion,
		IssuedAt: nilTime(st.DocIssuedAt), AppliedAt: nilTime(st.AppliedAt),
		NotAppliedHeartbeats: st.NotAppliedHeartbeats, Problems: st.Problems,
	}
	if v.Problems == nil {
		v.Problems = map[string]string{}
	}
	switch {
	case !st.Capabilities.Takes(agentproto.CapSettings):
		v.State = DocUnsupported
	case st.NotApplied():
		v.State = DocNotApplied
	case st.DocVersion > 0 && st.AppliedVersion >= st.DocVersion:
		v.State = DocApplied
	case st.DocVersion > 0 && online:
		v.State = DocPending
	case !online:
		v.State = DocWaiting
	}
	return v
}

// ProblemDevice is a device on the platform page's lists.
type ProblemDevice struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	OrganizationID       string `json:"organizationId"`
	OrganizationName     string `json:"organizationName"`
	AgentVersion         string `json:"agentVersion"`
	NotAppliedHeartbeats int    `json:"notAppliedHeartbeats"`
}

// Problems is what the platform page lists: the devices whose agent takes no
// settings, and those whose settings are not applied.
type Problems struct {
	Unsupported []ProblemDevice `json:"unsupported"`
	NotApplied  []ProblemDevice `json:"notApplied"`
}

const maxProblems = 500

// Problems lists them for super administrators.
func (s *Service) Problems(ctx context.Context, c access.Caller) (Problems, error) {
	if !c.CanGlobal(rbac.PermSettingsManage) {
		return Problems{}, apperr.Forbidden()
	}
	out := Problems{Unsupported: []ProblemDevice{}, NotApplied: []ProblemDevice{}}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT d.id::text, d.name, d.organization_id::text, o.name, coalesce(d.agent_version, ''),
				coalesce(s.not_applied_heartbeats, 0),
				coalesce((s.capabilities -> 'accepts') ? $1::text, false)
			FROM devices d
			JOIN organizations o ON o.id = d.organization_id
			LEFT JOIN agent_device_state s ON s.device_id = d.id
			WHERE d.enrolled_at IS NOT NULL AND NOT d.quick_assist
			  AND (NOT coalesce((s.capabilities -> 'accepts') ? $1::text, false) OR coalesce(s.not_applied_heartbeats, 0) >= $2)
			ORDER BY lower(o.name), lower(d.name), d.id LIMIT $3`, agentproto.CapSettings, NotAppliedAfter, 2*maxProblems)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				p     ProblemDevice
				takes bool
			)
			if err := rows.Scan(&p.ID, &p.Name, &p.OrganizationID, &p.OrganizationName, &p.AgentVersion, &p.NotAppliedHeartbeats, &takes); err != nil {
				return err
			}
			if takes {
				out.NotApplied = append(out.NotApplied, p)
			} else {
				out.Unsupported = append(out.Unsupported, p)
			}
		}
		return rows.Err()
	})
	return out, err
}
