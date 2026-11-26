package export

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/report"
)

// PDF writes the report as a plain PDF 1.4: a summary, the requirements, the plan of action and
// the system security plan, in Helvetica. It is written by hand (no library): text only.
func PDF(r *report.Report) []byte {
	var lines []string
	add := func(s string) { lines = append(lines, s) }
	add("#" + r.Title)
	add(r.Disclaimer)
	add("")
	add(fmt.Sprintf("Assessment state: %s. Framework: %s %s. Made %s.", r.State, r.Framework, r.Version, r.Generated.UTC().Format("2006-01-02 15:04 UTC")))
	if r.Assessor != "" {
		add("Assessor: " + r.Assessor)
	}
	add("")
	add("#Score range")
	if r.Score.Number != nil {
		add(fmt.Sprintf("Score: %d (nothing is left unassessed).", *r.Score.Number))
	} else {
		add(fmt.Sprintf("Score if the unassessed requirements fail: %d.", r.Score.Low))
		add(fmt.Sprintf("Score if the unassessed requirements pass: %d.", r.Score.High))
		add("No single number is shown while any requirement is unassessed.")
	}
	add(fmt.Sprintf("Met or not applicable: %d. Not met: %d. Not assessed: %d. Level 1 practices met: %d of %d.", r.Score.Met, r.Score.NotMet, r.Score.Unassessed, r.Score.L1Met, r.Score.L1Of))
	add(fmt.Sprintf("Reading of the plan-of-action rule (minimum score %d): %s.", r.Score.GateMin, r.Score.GateOutcome))
	add("EasyRMM does not post a score anywhere.")
	add("")
	add("#Scope")
	for _, s := range r.Scope {
		add(fmt.Sprintf("- %s (%s): %s", s.Name, s.Kind, s.Category))
	}
	add("")
	add("#Requirements")
	for _, q := range r.Requirements {
		add(fmt.Sprintf("%s  %s  [%s]", q.NistID, q.Title, q.Status))
		if q.Statement != "" {
			add("    " + q.Statement)
		}
	}
	add("")
	add("#Plan of action and milestones")
	for _, p := range r.POAM {
		add(fmt.Sprintf("%s  %d point(s)  %s  closes by %s", p.NistID, p.Points, p.Status, p.ClosesBy))
		if p.Weakness != "" {
			add("    " + p.Weakness)
		}
	}
	add("")
	for _, s := range r.SSP {
		add("#" + s.Heading)
		for _, l := range strings.Split(s.Body, "\n") {
			add(l)
		}
		add("")
	}
	return buildPDF(lines)
}

const (
	lineWidth    = 92
	linesPerPage = 52
)

func wrap(s string) []string {
	var out []string
	for len(s) > lineWidth {
		cut := strings.LastIndex(s[:lineWidth], " ")
		if cut < lineWidth/2 {
			cut = lineWidth
		}
		out = append(out, strings.TrimRight(s[:cut], " "))
		s = strings.TrimLeft(s[cut:], " ")
		s = "    " + s
	}
	return append(out, s)
}

// winAnsi keeps printable ASCII and maps the rest to a question mark, so that the text needs no font encoding.
func winAnsi(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c == '\t':
			b.WriteString("    ")
		case c >= 32 && c < 127:
			b.WriteRune(c)
		case c == '’' || c == '‘':
			b.WriteByte('\'')
		case c == '–' || c == '—':
			b.WriteByte('-')
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, "(", `\(`, ")", `\)`).Replace(s)
}

func buildPDF(src []string) []byte {
	type row struct {
		text string
		bold bool
	}
	var rows []row
	for _, l := range src {
		bold := strings.HasPrefix(l, "#")
		l = winAnsi(strings.TrimPrefix(l, "#"))
		for _, w := range wrap(l) {
			rows = append(rows, row{w, bold})
		}
	}
	var pages [][]row
	for len(rows) > 0 {
		n := min(linesPerPage, len(rows))
		pages = append(pages, rows[:n])
		rows = rows[n:]
	}
	if len(pages) == 0 {
		pages = [][]row{{}}
	}
	// Objects: 1 catalog, 2 pages, 3 font, 4 bold font, then a page and its content per page.
	var objs [][]byte
	objs = append(objs, []byte("<< /Type /Catalog /Pages 2 0 R >>"))
	var kids []string
	for i := range pages {
		kids = append(kids, fmt.Sprintf("%d 0 R", 5+2*i))
	}
	objs = append(objs, []byte(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages))))
	objs = append(objs, []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"))
	objs = append(objs, []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"))
	for i, p := range pages {
		var c bytes.Buffer
		c.WriteString("BT\n10 TL\n40 800 Td\n")
		for _, r := range p {
			f := "/F1"
			if r.bold {
				f = "/F2"
			}
			fmt.Fprintf(&c, "%s 9 Tf (%s) '\n", f, esc(r.text))
		}
		fmt.Fprintf(&c, "ET\nBT /F1 8 Tf 40 20 Td (Page %d of %d) Tj ET\n", i+1, len(pages))
		objs = append(objs, []byte(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents %d 0 R >>", 6+2*i)))
		objs = append(objs, []byte(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", c.Len(), c.String())))
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offs := make([]int, len(objs))
	for i, o := range objs {
		offs[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	x := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, x)
	return out.Bytes()
}
