package eventrules

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// Datum is one value of an event's data: a named EventData value, an unnamed
// one of a classic event (Name empty), or a leaf of UserData (Path holds the
// element path under UserData). A value the caller may not see is Hidden and
// holds nothing.
type Datum struct {
	Name   string `json:"name,omitempty"`
	Path   string `json:"path,omitempty"`
	Value  string `json:"value"`
	Hidden bool   `json:"hidden,omitempty"`
	Cut    bool   `json:"cut,omitempty"`
}

// Parsed is an event as its XML says it: what the server compares the
// builtin's fields with.
type Parsed struct {
	Provider, ProviderGUID string
	ID                     int
	Qualifiers             *int
	Version, Level, Task   int
	Opcode                 int
	Keywords               uint64
	Time                   string
	Record                 int64
	Channel, Computer      string
	UserSID                string
	PID, TID               int
	Data                   []Datum
	// Message is the rendered message, when the XML carries a RenderingInfo.
	Message    string
	HasMessage bool

	spans []span // the text of each data value and of the message, in the XML
}

type span struct {
	start, end int // byte offsets of the character data, or start == end where it is empty
	datum      int // index into Data, or -1 for the message
}

// ErrXML is an event whose XML cannot be read.
var ErrXML = errors.New("eventrules: the event's XML cannot be read")

type frame struct {
	name   string
	text   strings.Builder
	start  int
	end    int
	has    bool
	nChild int
	attrs  map[string]string
}

// ParseXML reads an event's XML with encoding/xml: the System fields and
// every data value, in order, with the places the values are in the text.
func ParseXML(x string) (*Parsed, error) {
	dec := xml.NewDecoder(strings.NewReader(x))
	dec.Strict = true
	p := &Parsed{}
	var stack []*frame
	inRendering := false
	for {
		before := int(dec.InputOffset())
		tok, err := dec.RawToken()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrXML, err)
		}
		after := int(dec.InputOffset())
		switch t := tok.(type) {
		case xml.StartElement:
			f := &frame{name: t.Name.Local, attrs: map[string]string{}}
			for _, a := range t.Attr {
				f.attrs[a.Name.Local] = a.Value
			}
			if len(stack) > 0 {
				stack[len(stack)-1].nChild++
			}
			stack = append(stack, f)
			if f.name == "RenderingInfo" {
				inRendering = true
			}
		case xml.CharData:
			if len(stack) == 0 {
				continue
			}
			f := stack[len(stack)-1]
			if !f.has {
				f.start, f.has = before, true
			}
			f.end = after
			f.text.Write(t)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("%w: unbalanced", ErrXML)
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			names := make([]string, len(stack))
			for i, s := range stack {
				names[i] = s.name
			}
			if f.name == "RenderingInfo" {
				inRendering = false
			}
			if err := p.leaf(f, names, inRendering); err != nil {
				return nil, err
			}
		}
	}
	if len(stack) != 0 || p.Record == 0 && p.Provider == "" {
		return nil, fmt.Errorf("%w: it is not an event", ErrXML)
	}
	return p, nil
}

// leaf takes in a closed element: names are its ancestors, outermost first.
func (p *Parsed) leaf(f *frame, names []string, inRendering bool) error {
	n := len(names)
	text := strings.TrimSpace(f.text.String())
	num := func() int {
		v, _ := strconv.Atoi(text)
		return v
	}
	under := func(parent string) bool { return n >= 1 && names[n-1] == parent }
	switch {
	case under("System") && n == 2:
		switch f.name {
		case "Provider":
			p.Provider, p.ProviderGUID = f.attrs["Name"], f.attrs["Guid"]
		case "EventID":
			p.ID = num()
			if q, ok := f.attrs["Qualifiers"]; ok {
				if v, err := strconv.Atoi(q); err == nil {
					p.Qualifiers = &v
				}
			}
		case "Version":
			p.Version = num()
		case "Level":
			p.Level = num()
		case "Task":
			p.Task = num()
		case "Opcode":
			p.Opcode = num()
		case "Keywords":
			v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(text), "0x"), 16, 64)
			if err == nil {
				p.Keywords = v
			}
		case "TimeCreated":
			p.Time = f.attrs["SystemTime"]
		case "EventRecordID":
			p.Record, _ = strconv.ParseInt(text, 10, 64)
		case "Execution":
			p.PID, _ = strconv.Atoi(f.attrs["ProcessID"])
			p.TID, _ = strconv.Atoi(f.attrs["ThreadID"])
		case "Channel":
			p.Channel = text
		case "Computer":
			p.Computer = text
		case "Security":
			p.UserSID = f.attrs["UserID"]
		}
	case inRendering && f.name == "Message" && under("RenderingInfo"):
		p.Message, p.HasMessage = text, true
		start, end := f.start, f.end
		if !f.has {
			start, end = -1, -1
		}
		p.spans = append(p.spans, span{start, end, -1})
	case f.nChild == 0 && n >= 2 && names[1] == "EventData":
		d := Datum{Name: f.attrs["Name"], Value: f.text.String()}
		if f.name == "Binary" {
			d.Name = "Binary"
		}
		p.addDatum(d, f)
	case f.nChild == 0 && n >= 2 && names[1] == "UserData":
		d := Datum{Name: f.name, Path: strings.Join(append(slices.Clone(names[2:]), f.name), "/"), Value: f.text.String()}
		p.addDatum(d, f)
	}
	return nil
}

func (p *Parsed) addDatum(d Datum, f *frame) {
	start, end := f.start, f.end
	if !f.has {
		start, end = -1, -1
	}
	p.Data = append(p.Data, d)
	p.spans = append(p.spans, span{start, end, len(p.Data) - 1})
}

// Sensitive returns the indexes of the data values the rules call sensitive
// in an event of the channel.
func (p *Parsed) Sensitive(channel string) []int {
	var out []int
	for i, d := range p.Data {
		if SensitiveField(channel, p.Provider, d.Name) {
			out = append(out, i)
		}
	}
	return out
}

// Rewrite returns the XML x, which p was parsed from, with the data values at
// the indexes in hide, and the rendered message when hideMessage is set,
// replaced by HiddenMarker, and every other value and the message cut to
// maxValue and maxMessage characters with CutMarker. Only character data
// changes; the rest of the text is as Windows wrote it. The fields get the
// same cuts (CutText), so that the server's comparison holds.
func (p *Parsed) Rewrite(x string, hide []int, hideMessage bool, maxValue, maxMessage int) string {
	type edit struct {
		start, end int
		to         string
	}
	var edits []edit
	esc := func(s string) string {
		var b bytes.Buffer
		_ = xml.EscapeText(&b, []byte(s))
		return b.String()
	}
	for _, s := range p.spans {
		if s.start < 0 || s.end > len(x) || s.start > s.end {
			continue
		}
		switch {
		case s.datum >= 0 && slices.Contains(hide, s.datum), s.datum < 0 && hideMessage:
			edits = append(edits, edit{s.start, s.end, esc(HiddenMarker)})
		default:
			limit, cur := maxValue, p.Message
			if s.datum >= 0 {
				cur = p.Data[s.datum].Value
			} else {
				limit = maxMessage
			}
			if cut, ok := CutText(cur, limit); ok {
				edits = append(edits, edit{s.start, s.end, esc(cut)})
			}
		}
	}
	slices.SortFunc(edits, func(a, b edit) int { return b.start - a.start })
	out := x
	for _, e := range edits {
		out = out[:e.start] + e.to + out[e.end:]
	}
	return out
}

// Redact is Rewrite without cuts.
func (p *Parsed) Redact(x string, hide []int, hideMessage bool) string {
	return p.Rewrite(x, hide, hideMessage, 1<<30, 1<<30)
}

// CutXML is Rewrite with cuts only.
func (p *Parsed) CutXML(x string, maxValue, maxMessage int) string {
	return p.Rewrite(x, nil, false, maxValue, maxMessage)
}

// CutText cuts s to max runes and ends it with CutMarker, reporting whether
// it did. A value that fits is returned as it is.
func CutText(s string, max int) (string, bool) {
	r := []rune(s)
	if len(r) <= max {
		return s, false
	}
	return string(r[:max]) + CutMarker, true
}

// SystemOnly returns the event's XML reduced to its System element, as a
// line too large for the list is sent.
func SystemOnly(x string) string {
	i := strings.Index(x, "<System>")
	j := strings.Index(x, "</System>")
	if i < 0 || j < i {
		return x
	}
	open := strings.Index(x, "<Event")
	k := strings.Index(x[open:], ">")
	if open < 0 || k < 0 {
		return x[i : j+len("</System>")]
	}
	head := x[open : open+k+1]
	return head + x[i:j+len("</System>")] + "</Event>"
}
