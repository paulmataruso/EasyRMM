package extract

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// maxMember bounds a zip member's size, so a damaged or hostile zip cannot
// exhaust memory; DISA's largest XCCDF file is under 1 MB.
const maxMember = 64 << 20

func newZip(b []byte) (*zip.Reader, error) {
	return zip.NewReader(bytes.NewReader(b), int64(len(b)))
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxMember+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMember {
		return nil, fmt.Errorf("%s is larger than %d bytes", f.Name, maxMember)
	}
	return b, nil
}

// stigRule is a rule as the extraction needs it. The check text is kept in
// memory to match rules across releases and never written.
type stigRule struct {
	version string // WN11-SO-000010
	id      string // SV-253256r991589_rule
	ccis    []string
	check   string
}

type stigRelease struct {
	version string // V2R11
	date    string // 2026-09-30
	rules   []stigRule
}

type xccdfBenchmark struct {
	Version   string `xml:"version"`
	PlainText []struct {
		ID   string `xml:"id,attr"`
		Text string `xml:",chardata"`
	} `xml:"plain-text"`
	Groups []struct {
		Rules []struct {
			ID      string `xml:"id,attr"`
			Version string `xml:"version"`
			Idents  []struct {
				System string `xml:"system,attr"`
				Value  string `xml:",chardata"`
			} `xml:"ident"`
			Check []struct {
				Content string `xml:"check-content"`
			} `xml:"check"`
		} `xml:"Rule"`
	} `xml:"Group"`
}

var releaseInfo = regexp.MustCompile(`Release:\s*(\d+)\s+Benchmark Date:\s*(\d{1,2} [A-Z][a-z]{2} \d{4})`)

const cciSystem = "http://cyber.mil/cci"

func parseSTIGZip(b []byte) (stigRelease, error) {
	x, err := zipMember(b, "-xccdf.xml")
	if err != nil {
		return stigRelease{}, err
	}
	return parseXCCDF(x)
}

func parseXCCDF(b []byte) (stigRelease, error) {
	var bm xccdfBenchmark
	if err := xml.Unmarshal(b, &bm); err != nil {
		return stigRelease{}, fmt.Errorf("XCCDF: %w", err)
	}
	var r stigRelease
	for _, p := range bm.PlainText {
		if p.ID != "release-info" {
			continue
		}
		m := releaseInfo.FindStringSubmatch(p.Text)
		if m == nil {
			return stigRelease{}, fmt.Errorf("XCCDF: release-info %q", p.Text)
		}
		d, err := time.Parse("2 Jan 2006", m[2])
		if err != nil {
			return stigRelease{}, fmt.Errorf("XCCDF: %w", err)
		}
		r.version = "V" + strings.TrimSpace(bm.Version) + "R" + m[1]
		r.date = d.Format(time.DateOnly)
	}
	if r.version == "" {
		return stigRelease{}, fmt.Errorf("XCCDF: no release-info")
	}
	seen := map[string]bool{}
	for _, g := range bm.Groups {
		for _, x := range g.Rules {
			rule := stigRule{version: strings.TrimSpace(x.Version), id: strings.TrimSpace(x.ID)}
			if rule.version == "" || rule.id == "" || seen[rule.version] {
				return stigRelease{}, fmt.Errorf("XCCDF: rule %q %q is unnamed or listed twice", rule.version, rule.id)
			}
			seen[rule.version] = true
			for _, id := range x.Idents {
				if id.System == cciSystem {
					rule.ccis = append(rule.ccis, strings.TrimSpace(id.Value))
				}
			}
			for _, c := range x.Check {
				rule.check += c.Content
			}
			r.rules = append(r.rules, rule)
		}
	}
	if len(r.rules) == 0 {
		return stigRelease{}, fmt.Errorf("XCCDF: no rules")
	}
	return r, nil
}

// cciRefs are a CCI's SP 800-53 references as the list writes them
// (AC-7 a, AC-6 (9)).
type cciRefs struct{ rev5, rev4 []string }

type cciList struct {
	version string
	date    string
	refs    map[string]cciRefs
}

type cciXML struct {
	Version     string `xml:"metadata>version"`
	PublishDate string `xml:"metadata>publishdate"`
	Items       []struct {
		ID   string `xml:"id,attr"`
		Refs []struct {
			Title string `xml:"title,attr"`
			Index string `xml:"index,attr"`
		} `xml:"references>reference"`
	} `xml:"cci_items>cci_item"`
}

// The CCI list's titles for the two SP 800-53 revisions.
const (
	rev5Title = "NIST SP 800-53 Revision 5"
	rev4Title = "NIST SP 800-53 Revision 4"
)

func parseCCIZip(b []byte) (cciList, error) {
	x, err := zipMember(b, "U_CCI_List.xml")
	if err != nil {
		return cciList{}, err
	}
	return parseCCI(x)
}

// utf8BOM starts DISA's CCI list.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

func parseCCI(b []byte) (cciList, error) {
	var x cciXML
	if err := xml.Unmarshal(bytes.TrimPrefix(b, utf8BOM), &x); err != nil {
		return cciList{}, fmt.Errorf("CCI list: %w", err)
	}
	l := cciList{version: strings.TrimSpace(x.Version), date: strings.TrimSpace(x.PublishDate), refs: map[string]cciRefs{}}
	for _, it := range x.Items {
		var r cciRefs
		for _, ref := range it.Refs {
			if strings.Contains(ref.Index, ";") {
				return cciList{}, fmt.Errorf("CCI list: %s: index %q holds the data files' separator", it.ID, ref.Index)
			}
			switch ref.Title {
			case rev5Title:
				r.rev5 = append(r.rev5, strings.TrimSpace(ref.Index))
			case rev4Title:
				r.rev4 = append(r.rev4, strings.TrimSpace(ref.Index))
			}
		}
		l.refs[it.ID] = r
	}
	if l.version == "" || len(l.refs) == 0 {
		return cciList{}, fmt.Errorf("CCI list: no version or no items")
	}
	return l, nil
}
