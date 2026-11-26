package jobs

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/registryrules"
)

// Export formats of a registry export (ADR-0067, Export).
const (
	ExportJSON = "json"
	ExportReg  = "reg"
)

// regHeader is the first line of every .reg file.
const regHeader = "Windows Registry Editor Version 5.00"

// regBuilder writes Registry Editor's text format.
type regBuilder struct {
	b      strings.Builder
	keys   int
	values int
}

func (w *regBuilder) line(s string) { w.b.WriteString(s + "\r\n") }

// regQuote writes text as a quoted string: a backslash and a double quote
// are escaped.
func regQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// hasControl reports whether s holds a control character a quoted string
// cannot carry on one line.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// hexBytes writes bytes as Registry Editor does after "hex:" or "hex(n):":
// two-digit hex numbers separated by commas, wrapped with a trailing
// backslash and two spaces of indent. prefix is what is already on the line.
func hexBytes(prefix string, data []byte) string {
	var b strings.Builder
	b.WriteString(prefix)
	col := len(prefix)
	for i, c := range data {
		item := fmt.Sprintf("%02x", c)
		if i < len(data)-1 {
			item += ","
		}
		if col+len(item) > 78 {
			b.WriteString("\\\r\n  ")
			col = 2
		}
		b.WriteString(item)
		col += len(item)
	}
	return b.String()
}

// regValueName is the left side of a value's line.
func regValueName(name string) string {
	if name == "" {
		return "@"
	}
	return regQuote(name)
}

// regValue writes one value, or says why it is left out: a masked value, a
// value too large to be in the export, a link's SymbolicLinkValue (never
// written, so that importing an export never makes a link), a value whose
// name is not valid text.
func (w *regBuilder) value(v agentproto.RegValue) {
	switch {
	case v.Masked:
		w.line("; value left out, masked: " + displayRegName(v.Name))
		return
	case v.Type == registryrules.TypeLink:
		w.line("; value left out, a link target: " + displayRegName(v.Name))
		return
	case v.Odd && v.RawName != "":
		w.line("; value left out, its name is not valid text: " + displayRegName(v.Name))
		return
	}
	data, ok := agentproto.RegValueBytes(v)
	if !ok || v.Cut {
		w.line("; value left out, its data is not in the export: " + displayRegName(v.Name))
		return
	}
	name := regValueName(v.Name)
	if hasControl(v.Name) {
		w.line("; value left out, its name holds a control character: " + displayRegName(v.Name))
		return
	}
	w.values++
	switch {
	case v.Type == registryrules.TypeSZ && v.Text != nil && !hasControl(*v.Text):
		w.line(name + "=" + regQuote(*v.Text))
	case v.Type == registryrules.TypeDWord && v.Number != nil:
		w.line(fmt.Sprintf("%s=dword:%08x", name, *v.Number))
	case v.Type == registryrules.TypeBinary:
		w.line(hexBytes(name+"=hex:", data))
	default:
		// hex(2) for REG_EXPAND_SZ, hex(7), hex(b) and the rest: the type
		// number in hex, as Registry Editor writes them.
		w.line(hexBytes(fmt.Sprintf("%s=hex(%x):", name, v.Type), data))
	}
}

func displayRegName(n string) string {
	if n == "" {
		return "(Default)"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 {
			return '?'
		}
		return r
	}, n)
}

// regKeyHeader writes a key's header line under its physical name, so that a
// key of the 32-bit view is under WOW6432Node.
func regKeyHeader(hive, view string, path []string) string {
	h := registryrules.Hive(hive)
	rh, _ := registryrules.Resolve(h, nil)
	names := registryrules.PhysicalNames(h, registryrules.View(view), path)
	return "[" + registryrules.Format(rh, names) + "]"
}

// BuildReg writes an export as a .reg file: UTF-16LE with a byte order mark
// and CRLF line ends. Comment lines name what was left out.
func BuildReg(res *agentproto.RegistryResult) []byte {
	w := &regBuilder{}
	w.line(regHeader)
	w.line("")
	b := res.Begin
	for _, x := range res.XKeys {
		path := regKeyHeader(b.Hive, b.View, x.Path)
		switch x.State {
		case agentproto.StateRefused:
			w.line("; key refused by EasyRMM and not exported: " + path)
			w.line("")
			continue
		case agentproto.StateDenied:
			w.line("; key left out, access denied: " + path)
			w.line("")
			continue
		case agentproto.StateLink:
			w.line("; key is a link, not followed: " + path + " -> " + x.Target)
			w.line("")
			continue
		}
		w.keys++
		w.line(path)
		for _, v := range x.Values {
			w.value(v)
		}
		for _, l := range x.Left {
			w.line("; " + l)
		}
		w.line("")
	}
	u := utf16.Encode([]rune(w.b.String()))
	out := make([]byte, 2, 2+2*len(u))
	binary.LittleEndian.PutUint16(out, 0xFEFF)
	for _, c := range u {
		out = binary.LittleEndian.AppendUint16(out, c)
	}
	return out
}

// exportDocument is the JSON export: the result as it is, with the device,
// the view, the time and the agent's version.
type exportDocument struct {
	Device       string               `json:"device"`
	Hive         string               `json:"hive"`
	View         string               `json:"view"`
	Path         []string             `json:"path"`
	ReadAt       string               `json:"readAt,omitempty"`
	AgentVersion string               `json:"agentVersion"`
	Rules        int                  `json:"rules"`
	Keys         []agentproto.RegXKey `json:"keys"`
}

// BuildJSON writes an export as JSON.
func BuildJSON(device string, readAt string, res *agentproto.RegistryResult) ([]byte, error) {
	b := res.Begin
	keys := res.XKeys
	if keys == nil {
		keys = []agentproto.RegXKey{}
	}
	return json.MarshalIndent(exportDocument{Device: device, Hive: b.Hive, View: b.View, Path: b.Path, ReadAt: readAt,
		AgentVersion: b.AgentVersion, Rules: b.Rules, Keys: keys}, "", "  ")
}
