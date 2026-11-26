package reports

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/posture"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Security report (ADR-0082): each computer's posture, one row per computer.
// It is the same posture the Devices list shows, read by the same code
// (posture.Load), so the report and the column cannot disagree.

var securityReport = definition{
	title:         "Security",
	perm:          rbac.PermDeviceView,
	privateSearch: true,
	columns: []Column{
		{"organization", "Organization", TypeText},
		{"site", "Site", TypeText},
		{"device", "Device", TypeText},
		{"platform", "Platform", TypeText},
		{"posture", "Security policy", TypeText},
		{"score", "Score", TypePercent},
		{"failing", "Controls not meeting", TypeNumber},
		{"cannotTell", "Controls that cannot be told", TypeNumber},
		{"complianceFailing", "Compliance checks not meeting", TypeNumber},
		{"reasons", "Reasons", TypeText},
		{"checkedAt", "Newest result", TypeTime},
	},
	run: func(ctx context.Context, tx pgx.Tx, q Query, out emit) error {
		type dev struct {
			posture.Ref
			site                      uuid.UUID
			orgName, siteName, device string
		}
		rows, err := tx.Query(ctx, `SELECT d.id, d.organization_id, d.site_id, o.name, st.name, d.name, d.platform, d.enrolled_at IS NOT NULL
			FROM devices d`+fromSQL+`
			WHERE `+scopeSQL+` AND d.platform IN ('linux', 'windows') AND d.enrolled_at IS NOT NULL
			  AND ($4 = '' OR lower(d.name) LIKE $4 ESCAPE '\' OR lower(d.hostname) LIKE $4 ESCAPE '\')
			ORDER BY lower(o.name), o.id, lower(st.name), st.id, lower(d.name), d.id`,
			nullID(q.OrganizationID), nullID(q.SiteID), q.Platform, likePattern(q.Search))
		if err != nil {
			return err
		}
		var devs []dev
		for rows.Next() {
			var d dev
			if err := rows.Scan(&d.ID, &d.Org, &d.site, &d.orgName, &d.siteName, &d.device, &d.Platform, &d.Enrolled); err != nil {
				rows.Close()
				return err
			}
			devs = append(devs, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		const chunk = 500
		now := time.Now()
		for start := 0; start < len(devs); start += chunk {
			part := devs[start:min(start+chunk, len(devs))]
			refs := make([]posture.Ref, len(part))
			ids := make([]uuid.UUID, len(part))
			for i, d := range part {
				refs[i], ids[i] = d.Ref, d.ID
			}
			m, err := posture.Load(ctx, tx, refs, now)
			if err != nil {
				return err
			}
			failing, err := complianceFailing(ctx, tx, ids)
			if err != nil {
				return err
			}
			for _, d := range part {
				p := m[d.ID]
				if p == nil || !posture.Matches(p, q.Posture) {
					continue // outside the dev scope, or a filter says no
				}
				reasons := make([]string, len(p.Reasons))
				for i, r := range p.Reasons {
					reasons[i] = posture.ReasonText(r)
				}
				var score, cf any
				if p.Percent != nil {
					score = *p.Percent
				}
				if n, ok := failing[d.ID]; ok {
					cf = n
				}
				row := []any{d.orgName, d.siteName, d.device, platformName(d.Platform), posture.Phrase(p.Word), score, p.Failing, p.CannotTell, cf,
					strings.Join(reasons, "; "), timeOrNil(p.CheckedAt)}
				if !out(d.Org, d.site, row) {
					return nil
				}
			}
		}
		return nil
	},
}

// complianceFailing counts, for the computers that have compliance results,
// the controls whose result does not meet (ADR-0078).
func complianceFailing(ctx context.Context, tx pgx.Tx, ids []uuid.UUID) (map[uuid.UUID]int, error) {
	rows, err := tx.Query(ctx, `SELECT device_id, count(*) FILTER (WHERE state IN ('not_in_place', 'partly', 'half_applied', 'failed'))
		FROM compliance_results WHERE device_id = ANY ($1) GROUP BY device_id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[uuid.UUID]int{}
	for rows.Next() {
		var d uuid.UUID
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			return nil, err
		}
		m[d] = n
	}
	return m, rows.Err()
}
