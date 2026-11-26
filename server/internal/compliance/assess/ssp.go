package assess

import (
	"fmt"
	"sort"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/report"
)

var categoryLabel = map[string]string{
	"cui": "Holds or handles controlled information", "security_protection": "Protects the systems that do",
	"contractor_risk_managed": "Managed by the organization's own risk decision", "specialized": "Specialized equipment",
	"out_of_scope": "Out of scope",
}

var statusLabel = map[string]string{Met: "met", NotMet: "not met", NotApplicable: "not applicable", NotAssessed: "not assessed"}

// Generated writes the text of a generated section from the assessment. The sections a person
// writes are not touched. A generated section says what the record says and nothing more: no
// status is invented, and nothing is called compliant or certified.
func Generated(kind string, r *report.Report) string {
	switch kind {
	case "scope":
		return scopeText(r)
	case "requirements":
		return requirementsText(r)
	case "poam":
		return poamText(r)
	case "score":
		return scoreText(r)
	}
	return ""
}

func scopeText(r *report.Report) string {
	if len(r.Scope) == 0 {
		return "The scope has not been recorded yet."
	}
	by := map[string][]string{}
	for _, s := range r.Scope {
		by[s.Category] = append(by[s.Category], s.Name+" ("+s.Kind+")")
	}
	var cats []string
	for c := range by {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	var b strings.Builder
	for _, c := range cats {
		sort.Strings(by[c])
		fmt.Fprintf(&b, "%s:\n", label(categoryLabel, c))
		for _, n := range by[c] {
			b.WriteString("  - " + n + "\n")
		}
	}
	b.WriteString("Anything listed as out of scope is shown here on purpose and is not counted in the results.")
	return b.String()
}

func label(m map[string]string, k string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return k
}

func requirementsText(r *report.Report) string {
	fams := map[string][]report.Requirement{}
	var order []string
	for _, q := range r.Requirements {
		if _, ok := fams[q.Family]; !ok {
			order = append(order, q.Family)
		}
		fams[q.Family] = append(fams[q.Family], q)
	}
	sort.Strings(order)
	var b strings.Builder
	for _, f := range order {
		fmt.Fprintf(&b, "Family %s\n", f)
		for _, q := range fams[f] {
			fmt.Fprintf(&b, "%s %s: %s.", q.NistID, q.Title, label(statusLabel, q.Status))
			if s := strings.TrimSpace(q.Statement); s != "" {
				b.WriteString(" " + s)
			} else {
				b.WriteString(" No statement has been written yet.")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return strings.TrimSpace(b.String())
}

func poamText(r *report.Report) string {
	if len(r.POAM) == 0 {
		return "There are no plan of action items."
	}
	var b strings.Builder
	for _, p := range r.POAM {
		fmt.Fprintf(&b, "%s: %d point(s), %s, closes by %s.", p.NistID, p.Points, p.Status, p.ClosesBy)
		if !p.Eligible {
			b.WriteString(" This requirement may not be on a plan of action.")
		}
		b.WriteString("\n")
	}
	b.WriteString("A plan of action does not make a requirement met: a requirement not yet implemented scores as not met until it is.")
	return b.String()
}

func scoreText(r *report.Report) string {
	s := r.Score
	if s.Number != nil {
		return fmt.Sprintf("Score: %d. Every requirement has been assessed.", *s.Number)
	}
	return fmt.Sprintf("Score if the requirements not yet assessed fail: %d.\nScore if they pass: %d.\n%d requirement(s) are not yet assessed, so no single number is given.", s.Low, s.High, s.Unassessed)
}
