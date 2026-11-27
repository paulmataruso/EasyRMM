package grouppolicy

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"unicode"
)

// The "every setting" view (ADR-0083, section 2): Get-GPOReport -ReportType Xml, parsed on the server into a tree of
// Computer and User configuration, each extension and each setting with its state and value. What the console shows is
// what Microsoft's own report engine says; nothing here knows what a setting means.

const (
	// maxReportXML bounds the report after it is decompressed.
	maxReportXML = 16 << 20
	maxDepth     = 64
	// maxStored bounds the parsed tree as it is stored (the result limit is 64 KiB).
	maxStored = 60000
	// ReadOnlyNote is shown on every area no supported API changes (ADR-0083, section 5).
	ReadOnlyNote = "Read-only here: no supported API changes this. Use the Group Policy Management Console."
)

// Node is one line of the settings tree: a setting, a part of it, or a value.
type Node struct {
	Label    string `json:"label"`
	Value    string `json:"value,omitempty"`
	State    string `json:"state,omitempty"`
	Children []Node `json:"children,omitempty"`
}

// Extension is one client-side extension's settings: Registry (Administrative Templates), Security, Scripts, and so on.
type Extension struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	// NoAPI marks the areas no supported API writes, ever (Software Installation, wired and wireless network, IP
	// security): the console shows ReadOnlyNote on them.
	NoAPI    bool   `json:"noApi"`
	Settings []Node `json:"settings"`
}

// Config is the computer or the user half of a GPO.
type Config struct {
	Enabled    bool        `json:"enabled"`
	Version    Version     `json:"version"`
	Extensions []Extension `json:"extensions"`
}

// Report is group_policy.gpo_report's stored result.
type Report struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Created  string       `json:"created"`
	Modified string       `json:"modified"`
	Computer Config       `json:"computer"`
	User     Config       `json:"user"`
	Links    []ReportLink `json:"links"`
	// Findings are things worth a look the report shows: a stored preference password.
	Findings []string `json:"findings"`
	// Truncated says the tree was cut to fit the result's limit.
	Truncated bool `json:"truncated"`
	// Settings counts the nodes kept; Total counts the ones the report had.
	Settings int `json:"settings"`
	Total    int `json:"total"`
}

// reportEnvelope is what the script prints: the report, gzipped and in base64, with the GPO's identity.
type reportEnvelope struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	XML  string `json:"xmlGzip"`
}

// decodeReport is the catalog's decoder of gpo_report: the script's gzipped XML in, the parsed tree out.
func decodeReport(data json.RawMessage) (json.RawMessage, error) {
	var env reportEnvelope
	if err := decodeEnvelope(data, &env); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(env.XML)
	if err != nil {
		return nil, errors.New("the report is not base64")
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("the report is not gzip")
	}
	defer func() { _ = zr.Close() }()
	xmlBytes, err := io.ReadAll(io.LimitReader(zr, maxReportXML+1))
	if err != nil || len(xmlBytes) > maxReportXML {
		return nil, errors.New("the report is too large")
	}
	budget := 4000
	for {
		rep, err := ParseReport(xmlBytes, budget)
		if err != nil {
			return nil, err
		}
		if rep.ID == "" {
			rep.ID = env.ID
		}
		if rep.Name == "" {
			rep.Name = env.Name
		}
		out, err := json.Marshal(rep)
		if err != nil {
			return nil, err
		}
		if len(out) <= maxStored || budget < 20 {
			return out, nil
		}
		budget = budget * 2 / 3
	}
}

func decodeEnvelope(data json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return errors.New("the data does not match the action's result schema")
	}
	return nil
}

// elem is a parsed XML element, without its namespace.
type elem struct {
	name  string
	attrs [][2]string
	text  string
	kids  []*elem
}

func (e *elem) child(name string) *elem {
	for _, k := range e.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}

func (e *elem) childText(name string) string {
	if k := e.child(name); k != nil {
		return strings.TrimSpace(k.text)
	}
	return ""
}

func (e *elem) attr(name string) string {
	for _, a := range e.attrs {
		if a[0] == name {
			return a[1]
		}
	}
	return ""
}

func parseTree(xmlBytes []byte) (*elem, error) {
	dec := xml.NewDecoder(bytes.NewReader(xmlBytes))
	dec.Strict = true
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	var stack []*elem
	var root *elem
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("the report is not valid XML")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) >= maxDepth {
				return nil, errors.New("the report is nested too deep")
			}
			e := &elem{name: t.Name.Local}
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
					continue
				}
				e.attrs = append(e.attrs, [2]string{a.Name.Local, a.Value})
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.kids = append(p.kids, e)
			} else {
				root = e
			}
			stack = append(stack, e)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			if len(stack) > 0 {
				e := stack[len(stack)-1]
				if len(e.text) < 4096 {
					e.text += string(t)
				}
			}
		}
	}
	if root == nil || root.name != "GPO" {
		return nil, errors.New("the report is not a GPO report")
	}
	return root, nil
}

type builder struct {
	budget int
	total  int
	kept   int
	cut    bool
}

// ParseReport parses a Get-GPOReport XML document. budget is the most setting lines kept; the rest are counted and
// the report says it was cut.
func ParseReport(xmlBytes []byte, budget int) (*Report, error) {
	root, err := parseTree(xmlBytes)
	if err != nil {
		return nil, err
	}
	b := &builder{budget: budget}
	rep := &Report{
		Name: root.childText("Name"), Created: root.childText("CreatedTime"), Modified: root.childText("ModifiedTime"),
		Links: []ReportLink{}, Findings: []string{},
	}
	if id := root.child("Identifier"); id != nil {
		rep.ID = strings.ToLower(strings.Trim(strings.TrimSpace(id.childText("Identifier")), "{}"))
	}
	rep.Computer = b.config(root.child("Computer"))
	rep.User = b.config(root.child("User"))
	for _, k := range root.kids {
		if k.name != "LinksTo" {
			continue
		}
		l := ReportLink{Name: k.childText("SOMName"), Path: k.childText("SOMPath"), Enabled: strings.EqualFold(k.childText("Enabled"), "true"),
			Enforced: strings.EqualFold(k.childText("NoOverride"), "true")}
		rep.Links = append(rep.Links, l)
	}
	rep.Truncated, rep.Settings, rep.Total = b.cut, b.kept, b.total
	if bytes.Contains(bytes.ToLower(xmlBytes), []byte("cpassword")) {
		rep.Findings = append(rep.Findings, "A Group Policy Preferences item holds a stored password (cpassword). Any domain user can decrypt it (Microsoft security bulletin MS14-025). Remove the item and change the password.")
	}
	return rep, nil
}

func (b *builder) config(e *elem) Config {
	c := Config{Extensions: []Extension{}}
	if e == nil {
		return c
	}
	c.Enabled = strings.EqualFold(e.childText("Enabled"), "true")
	c.Version = Version{Directory: atoi(e.childText("VersionDirectory")), Sysvol: atoi(e.childText("VersionSysvol"))}
	for _, ed := range e.kids {
		if ed.name != "ExtensionData" {
			continue
		}
		ext := ed.child("Extension")
		x := Extension{Name: ed.childText("Name"), Settings: []Node{}}
		if ext != nil {
			kind := ext.attr("type")
			if _, after, ok := strings.Cut(kind, ":"); ok {
				kind = after
			}
			x.Kind = kind
			for _, k := range ext.kids {
				if n, ok := b.node(k, 0); ok {
					x.Settings = append(x.Settings, n)
				}
			}
		}
		x.NoAPI = noAPI(x.Name, x.Kind)
		c.Extensions = append(c.Extensions, x)
	}
	return c
}

// noAPI recognizes the areas ADR-0083 section 5 names: Software Installation, wired and wireless network policies and
// IP security policies.
func noAPI(name, kind string) bool {
	s := strings.ToLower(name + " " + kind)
	for _, w := range []string{"software installation", "softwareinstallation", "wired", "wireless", "ip security", "ipsecurity", "ipsec"} {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
		if n > 1<<30 {
			return 0
		}
	}
	return n
}

// spaced turns CamelCase into words: "SystemAccessPolicyName" is "System Access Policy Name".
func spaced(s string) string {
	var out []rune
	rs := []rune(s)
	for i, r := range rs {
		if i > 0 && unicode.IsUpper(r) && (unicode.IsLower(rs[i-1]) || (i+1 < len(rs) && unicode.IsLower(rs[i+1]) && unicode.IsUpper(rs[i-1]))) {
			out = append(out, ' ')
		}
		out = append(out, r)
	}
	return string(out)
}

func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return string(r)
}

// node turns an element into a line of the tree. A registry policy keeps its name and state; any other element keeps its
// name (or its Name child) and its text, its attributes and its children, so a setting no extension of ours knows
// still reads as GPMC would show it.
func (b *builder) node(e *elem, depth int) (Node, bool) {
	b.total++
	if b.kept >= b.budget {
		b.cut = true
		return Node{}, false
	}
	b.kept++
	n := Node{Label: spaced(e.name)}
	skip := map[string]bool{}
	if name := e.childText("Name"); name != "" && len(e.kids) > 1 {
		n.Label, skip["Name"] = name, true
	}
	if st := e.childText("State"); st != "" && e.name == "Policy" {
		n.State, skip["State"] = st, true
	}
	if len(e.kids) == 0 {
		n.Value = clip(e.text, 600)
	}
	for _, a := range e.attrs {
		if a[0] == "type" || a[0] == "nil" {
			continue
		}
		v := clip(a[1], 300)
		if strings.EqualFold(a[0], "cpassword") {
			v = "(stored password hidden)"
		}
		if b.kept < b.budget {
			b.kept++
			b.total++
			n.Children = append(n.Children, Node{Label: spaced(a[0]), Value: v})
		} else {
			b.cut = true
		}
	}
	if depth < maxDepth {
		for _, k := range e.kids {
			if skip[k.name] {
				continue
			}
			if c, ok := b.node(k, depth+1); ok {
				if k.name == "Explain" {
					c.Value = clip(c.Value, 400)
				}
				n.Children = append(n.Children, c)
			}
		}
	}
	return n, true
}
