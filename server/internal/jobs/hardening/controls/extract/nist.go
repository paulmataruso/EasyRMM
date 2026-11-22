package extract

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// catalogInfo is an OSCAL catalog's version and date.
type catalogInfo struct{ version, date string }

type oscalControl struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Props []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Class string `json:"class"`
	} `json:"props"`
	Links []struct {
		Href string `json:"href"`
		Rel  string `json:"rel"`
	} `json:"links"`
}

// prop returns the control's property of that name without a class: the
// catalog also gives zero-padded labels (AC-07) with a class.
func (c oscalControl) prop(name string) string {
	for _, p := range c.Props {
		if p.Name == name && p.Class == "" {
			return p.Value
		}
	}
	return ""
}

type oscalCatalog struct {
	Catalog struct {
		Metadata struct {
			Version      string `json:"version"`
			LastModified string `json:"last-modified"`
		} `json:"metadata"`
		Groups []struct {
			Controls []oscalControl `json:"controls"`
		} `json:"groups"`
		BackMatter struct {
			Resources []struct {
				UUID   string `json:"uuid"`
				Title  string `json:"title"`
				Rlinks []struct {
					Href string `json:"href"`
				} `json:"rlinks"`
			} `json:"resources"`
		} `json:"back-matter"`
	} `json:"catalog"`
}

func parseOSCAL(b []byte) (oscalCatalog, catalogInfo, error) {
	var c oscalCatalog
	if err := json.Unmarshal(b, &c); err != nil {
		return oscalCatalog{}, catalogInfo{}, fmt.Errorf("OSCAL: %w", err)
	}
	m := c.Catalog.Metadata
	if m.Version == "" || len(m.LastModified) < len("2006-01-02") {
		return oscalCatalog{}, catalogInfo{}, fmt.Errorf("OSCAL: no version or date")
	}
	return c, catalogInfo{version: m.Version, date: m.LastModified[:len("2006-01-02")]}, nil
}

// baseControl is an SP 800-53 Rev. 5 base control and its title.
type baseControl struct{ id, title string }

// parseCatalog reads the SP 800-53 Rev. 5 catalog's base controls that
// are not withdrawn.
func parseCatalog(b []byte) ([]baseControl, catalogInfo, error) {
	c, info, err := parseOSCAL(b)
	if err != nil {
		return nil, catalogInfo{}, err
	}
	out := []baseControl{}
	for _, g := range c.Catalog.Groups {
		for _, ctl := range g.Controls {
			if ctl.prop("status") == "withdrawn" {
				continue
			}
			label := ctl.prop("label")
			if label == "" || ctl.Title == "" {
				return nil, catalogInfo{}, fmt.Errorf("OSCAL: control %s has no label or title", ctl.ID)
			}
			out = append(out, baseControl{id: label, title: ctl.Title})
		}
	}
	if len(out) == 0 {
		return nil, catalogInfo{}, fmt.Errorf("OSCAL: no controls")
	}
	return out, info, nil
}

// rev3Requirement is an SP 800-171 Rev. 3 requirement and its source
// controls as NIST writes them (AC-02(03)).
type rev3Requirement struct {
	id       string
	controls []string
}

// parseRev3 reads the SP 800-171 Rev. 3 catalog: each requirement that is
// not withdrawn, and the SP 800-53 controls its references link to, which
// are its source controls.
func parseRev3(b []byte) ([]rev3Requirement, catalogInfo, error) {
	c, info, err := parseOSCAL(b)
	if err != nil {
		return nil, catalogInfo{}, err
	}
	sp80053 := map[string]string{} // resource uuid → control
	for _, r := range c.Catalog.BackMatter.Resources {
		for _, l := range r.Rlinks {
			if strings.Contains(l.Href, "/framework/version/SP_800_53_") {
				sp80053[r.UUID] = r.Title
			}
		}
	}
	out := []rev3Requirement{}
	for _, g := range c.Catalog.Groups {
		for _, ctl := range g.Controls {
			if ctl.prop("status") == "withdrawn" {
				continue
			}
			r := rev3Requirement{id: ctl.prop("sort-id")}
			for _, l := range ctl.Links {
				if ref, ok := sp80053[strings.TrimPrefix(l.Href, "#")]; ok && l.Rel == "reference" {
					r.controls = append(r.controls, ref)
				}
			}
			if r.id == "" || len(r.controls) == 0 {
				return nil, catalogInfo{}, fmt.Errorf("OSCAL: requirement %s has no sort-id or no source control", ctl.ID)
			}
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, catalogInfo{}, fmt.Errorf("OSCAL: no requirements")
	}
	return out, info, nil
}

// appendixDRow is a row of one of SP 800-171 Rev. 2's Tables D-1 to D-14:
// the requirements in it and the SP 800-53 Rev. 4 controls it lists.
type appendixDRow struct{ requirements, controls []string }

var (
	adRequirement = regexp.MustCompile(`^\s*(3\.\d{1,2}\.\d{1,2})\s`)
	adControl     = regexp.MustCompile(`[A-Z]{2}-\d{1,2}(?:\(\d{1,2}\))?`)
	adFootnote    = regexp.MustCompile(`^\s*\d{2} [A-Z]`)
)

// parseAppendixD reads Tables D-1 to D-14 from pdftotext -layout's output.
// A table's basic requirements share one row (the tables merge their
// cells); a derived requirement starts a row when a control stands on its
// first line, and otherwise shares the row above it, as 3.5.7 to 3.5.10
// share IA-5(1). Footnotes, page headers and footers are skipped.
func parseAppendixD(text string) ([]appendixDRow, error) {
	start := strings.Index(text, "TABLE D-1:")
	if start < 0 {
		return nil, fmt.Errorf("appendix D: no TABLE D-1")
	}
	end := strings.Index(text[start:], "APPENDIX E")
	if end < 0 {
		return nil, fmt.Errorf("appendix D: no APPENDIX E after it")
	}
	var rows []appendixDRow
	cur := -1 // the row being read
	section := ""
	inFootnote := false
	for _, line := range strings.Split(text[start:start+end], "\n") {
		s := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(s, "APPENDIX D") && strings.Contains(s, "PAGE"):
			inFootnote = false
			continue
		case inFootnote:
			continue
		case adFootnote.MatchString(line):
			inFootnote = true
			continue
		case s == "", strings.HasPrefix(s, "SP 800-171, REVISION 2"), strings.HasPrefix(s, "____"),
			strings.HasPrefix(s, "This publication is available"), strings.HasPrefix(s, "TABLE D-"),
			strings.HasPrefix(s, "NIST SP 800-53"), strings.HasPrefix(s, "SECURITY REQUIREMENTS"):
			continue
		case strings.HasPrefix(s, "Basic Security Requirements"):
			section, cur = "basic", -1
			continue
		case strings.HasPrefix(s, "Derived Security Requirements"):
			section, cur = "derived", -1
			continue
		}
		ctls := appendixDControls(line)
		if m := adRequirement.FindStringSubmatch(line); m != nil {
			switch {
			case section == "":
				return nil, fmt.Errorf("appendix D: %s outside a section", m[1])
			case cur >= 0 && (section == "basic" || len(ctls) == 0):
				rows[cur].requirements = append(rows[cur].requirements, m[1])
			default:
				rows = append(rows, appendixDRow{requirements: []string{m[1]}})
				cur = len(rows) - 1
			}
		}
		if len(ctls) > 0 {
			if cur < 0 {
				return nil, fmt.Errorf("appendix D: %v before any requirement", ctls)
			}
			rows[cur].controls = append(rows[cur].controls, ctls...)
		}
	}
	return checkAppendixD(rows)
}

// appendixDControls returns the SP 800-53 controls on a line: AC-6 or
// AC-6(1) standing on its own, not inside a longer word or number.
func appendixDControls(line string) []string {
	var out []string
	for _, m := range adControl.FindAllStringIndex(line, -1) {
		if m[0] > 0 && strings.ContainsRune(alnum+".", rune(line[m[0]-1])) {
			continue
		}
		if m[1] < len(line) && strings.ContainsRune(alnum+"(", rune(line[m[1]])) {
			continue
		}
		out = append(out, line[m[0]:m[1]])
	}
	return out
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func checkAppendixD(rows []appendixDRow) ([]appendixDRow, error) {
	if len(rows) == 0 {
		return nil, fmt.Errorf("appendix D: no rows")
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if len(r.controls) == 0 {
			return nil, fmt.Errorf("appendix D: %v lists no control", r.requirements)
		}
		for _, q := range r.requirements {
			if seen[q] {
				return nil, fmt.Errorf("appendix D: %s twice", q)
			}
			seen[q] = true
		}
	}
	return rows, nil
}

// crosswalkRow is an SP 800-53 Rev. 5 control or enhancement as the
// crosswalk writes it (AC-07) and the ISO/IEC 27001:2022 Annex A numbers it
// gives for it; the crosswalk's clause numbers (5.2, 7.5.1) are left out.
type crosswalkRow struct {
	control string
	annexA  []string
}

var annexA = regexp.MustCompile(`^A\.\d+\.\d+$`)

// parseCrosswalk reads NIST's OLIR spreadsheet: every sheet whose header
// row names the focal and reference document elements.
func parseCrosswalk(b []byte) ([]crosswalkRow, error) {
	sheets, err := readXLSX(b)
	if err != nil {
		return nil, err
	}
	var order []string
	byControl := map[string][]string{}
	for _, sheet := range sheets {
		if len(sheet) == 0 {
			continue
		}
		focal := slices.Index(sheet[0], "Focal Document Element")
		ref := slices.Index(sheet[0], "Reference Document Element")
		if focal < 0 || ref < 0 {
			continue
		}
		for _, row := range sheet[1:] {
			ctl, a := cell(row, focal), cell(row, ref)
			if ctl == "" || !annexA.MatchString(a) {
				continue
			}
			if _, ok := byControl[ctl]; !ok {
				order = append(order, ctl)
			}
			if !slices.Contains(byControl[ctl], a) {
				byControl[ctl] = append(byControl[ctl], a)
			}
		}
	}
	if len(order) == 0 {
		return nil, fmt.Errorf("crosswalk: no Annex A mappings")
	}
	out := make([]crosswalkRow, 0, len(order))
	for _, c := range order {
		out = append(out, crosswalkRow{control: c, annexA: byControl[c]})
	}
	return out, nil
}

func cell(row []string, i int) string {
	if i < len(row) {
		return row[i]
	}
	return ""
}

// readXLSX returns each worksheet's rows, in workbook order, with every
// cell's text whitespace-normalized and placed in its column.
func readXLSX(b []byte) ([][][]string, error) {
	zr, err := newZip(b)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		if files[f.Name], err = readZipFile(f); err != nil {
			return nil, err
		}
	}
	var shared []string
	if b, ok := files["xl/sharedStrings.xml"]; ok {
		var sst struct {
			SI []struct {
				Text []string `xml:"t"`
				Runs []struct {
					Text string `xml:"t"`
				} `xml:"r"`
			} `xml:"si"`
		}
		if err := xml.Unmarshal(b, &sst); err != nil {
			return nil, fmt.Errorf("xlsx: shared strings: %w", err)
		}
		for _, si := range sst.SI {
			s := strings.Join(si.Text, "")
			for _, r := range si.Runs {
				s += r.Text
			}
			shared = append(shared, s)
		}
	}
	var wb struct {
		Sheets []struct {
			RID string `xml:"http://schemas.openxmlformats.org/officeDocument/2006/relationships id,attr"`
		} `xml:"sheets>sheet"`
	}
	if err := xml.Unmarshal(files["xl/workbook.xml"], &wb); err != nil {
		return nil, fmt.Errorf("xlsx: workbook: %w", err)
	}
	var rels struct {
		Rel []struct {
			ID     string `xml:"Id,attr"`
			Target string `xml:"Target,attr"`
		} `xml:"Relationship"`
	}
	if err := xml.Unmarshal(files["xl/_rels/workbook.xml.rels"], &rels); err != nil {
		return nil, fmt.Errorf("xlsx: workbook relationships: %w", err)
	}
	targets := map[string]string{}
	for _, r := range rels.Rel {
		t := strings.TrimPrefix(r.Target, "/")
		if !strings.HasPrefix(t, "xl/") {
			t = path.Join("xl", t)
		}
		targets[r.ID] = t
	}
	var out [][][]string
	for _, s := range wb.Sheets {
		sheet, err := readSheet(files[targets[s.RID]], shared)
		if err != nil {
			return nil, fmt.Errorf("xlsx: sheet %s: %w", targets[s.RID], err)
		}
		out = append(out, sheet)
	}
	return out, nil
}

func readSheet(b []byte, shared []string) ([][]string, error) {
	var ws struct {
		Rows []struct {
			Cells []struct {
				Ref    string `xml:"r,attr"`
				Type   string `xml:"t,attr"`
				Value  string `xml:"v"`
				Inline string `xml:"is>t"`
			} `xml:"c"`
		} `xml:"sheetData>row"`
	}
	if err := xml.Unmarshal(b, &ws); err != nil {
		return nil, err
	}
	var out [][]string
	for _, r := range ws.Rows {
		var row []string
		for _, c := range r.Cells {
			col, err := column(c.Ref)
			if err != nil {
				return nil, err
			}
			v := c.Value
			switch c.Type {
			case "s":
				i, err := strconv.Atoi(c.Value)
				if err != nil || i < 0 || i >= len(shared) {
					return nil, fmt.Errorf("cell %s: shared string %q", c.Ref, c.Value)
				}
				v = shared[i]
			case "inlineStr":
				v = c.Inline
			}
			for len(row) <= col {
				row = append(row, "")
			}
			row[col] = strings.Join(strings.Fields(strings.ReplaceAll(v, "_x000D_", " ")), " ")
		}
		out = append(out, row)
	}
	return out, nil
}

// column returns a cell reference's zero-based column (B7 → 1).
func column(ref string) (int, error) {
	n := 0
	for _, ch := range ref {
		if ch < 'A' || ch > 'Z' {
			break
		}
		n = n*26 + int(ch-'A'+1)
	}
	if n == 0 || n > 16384 {
		return 0, fmt.Errorf("cell reference %q", ref)
	}
	return n - 1, nil
}
