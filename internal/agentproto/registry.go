package agentproto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/internal/registryrules"
)

// The registry editor's input and result (ADR-0067). Both sides compile
// these types, so that what the server checks and what the agent writes are
// one shape.

// Versions of the registry input and result.
const (
	RegistryInputVersion  = 1
	RegistryResultVersion = 1
)

// Operations of the registry builtin. "prepare" and the writes come with
// slice 2.
const (
	RegOpList   = "list"
	RegOpValue  = "value"
	RegOpSearch = "search"
	RegOpExport = "export"
)

// Limits of a registry read (ADR-0067, Types, encoding and limits; Search;
// Export).
const (
	RegMaxSubkeys     = 1000
	RegMaxValues      = 500
	RegPageBytes      = 1 << 20
	RegValuePageBytes = 4 << 10
	RegValueReadBytes = 1 << 20
	RegMaxTerm        = 256
	RegDefaultDepth   = 10
	RegMaxDepth       = 32
	RegMaxMatches     = 500
	RegMaxVisited     = 100000
	RegMaxExportKeys  = 5000
	// RegSearchSeconds and RegListSeconds are how long the builtin works
	// before it writes what it has and ends.
	RegSearchSeconds = 45
	RegListSeconds   = 30
)

// RegistryCursor says where the next page of a key's subkeys and values
// starts: after the named one, in ordinal ignore-case order.
type RegistryCursor struct {
	Subkey *string `json:"subkey,omitempty"`
	Value  *string `json:"value,omitempty"`
}

// RegistryInput is the input of a registry query (version 1).
type RegistryInput struct {
	V    int      `json:"v"`
	Op   string   `json:"op"`
	Hive string   `json:"hive"`
	View string   `json:"view"`
	Path []string `json:"path"`
	// ValueName is the value a "value" read asks for; "" is the default.
	ValueName *string `json:"valueName,omitempty"`
	// Cursor and the limits are for "list".
	Cursor     *RegistryCursor `json:"cursor,omitempty"`
	MaxSubkeys int             `json:"maxSubkeys,omitempty"`
	MaxValues  int             `json:"maxValues,omitempty"`
	// Term, Depth and MaxMatches are for "search".
	Term       string `json:"term,omitempty"`
	Depth      int    `json:"depth,omitempty"`
	MaxMatches int    `json:"maxMatches,omitempty"`
	// Rules is the version of the registry rules the server applied.
	Rules int `json:"rules"`
}

// ErrRegistryInput is an input the registry builtin does not accept.
var ErrRegistryInput = errors.New("agentproto: the registry input is not valid")

// DecodeRegistryInput reads an input strictly: one JSON object, no unknown
// field, nothing after it.
func DecodeRegistryInput(b []byte) (RegistryInput, error) {
	var in RegistryInput
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, fmt.Errorf("%w: %w", ErrRegistryInput, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return in, fmt.Errorf("%w: more than one document", ErrRegistryInput)
	}
	return in, in.Check()
}

// Check applies the rules every field is held to: the server when a query is
// created, and the agent again against the rules it was built with. A path
// that is refused is not an error here; Refused says so.
func (in RegistryInput) Check() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrRegistryInput, fmt.Sprintf(format, a...))
	}
	if in.V != RegistryInputVersion {
		return bad("version %d is not known", in.V)
	}
	switch in.Op {
	case RegOpList, RegOpValue, RegOpSearch, RegOpExport:
	default:
		return bad("operation %q is not known", in.Op)
	}
	if !registryrules.Hive(in.Hive).Valid() || !registryrules.View(in.View).Valid() {
		return bad("the hive or the view is not known")
	}
	if err := registryrules.ValidateNames(in.Path); err != nil {
		return bad("%v", err)
	}
	if in.Op == RegOpValue {
		if in.ValueName == nil {
			return bad("a value read names the value")
		}
		if err := registryrules.ValidateValueName(*in.ValueName); err != nil {
			return bad("%v", err)
		}
	} else if in.ValueName != nil {
		return bad("only a value read names a value")
	}
	if in.Op != RegOpList && (in.Cursor != nil || in.MaxSubkeys != 0 || in.MaxValues != 0) {
		return bad("a cursor and page limits are for a list")
	}
	if in.Op == RegOpList {
		if in.MaxSubkeys < 0 || in.MaxSubkeys > RegMaxSubkeys || in.MaxValues < 0 || in.MaxValues > RegMaxValues {
			return bad("a page holds at most %d subkeys and %d values", RegMaxSubkeys, RegMaxValues)
		}
		if in.Cursor != nil {
			for _, c := range []*string{in.Cursor.Subkey, in.Cursor.Value} {
				if c != nil && registryrules.ValidateValueName(*c) != nil {
					return bad("the cursor is not valid")
				}
			}
		}
	}
	if in.Op == RegOpSearch {
		n := utf8.RuneCountInString(in.Term)
		if n < 1 || n > RegMaxTerm || !utf8.ValidString(in.Term) || strings.ContainsRune(in.Term, 0) {
			return bad("a search term has 1 to %d characters", RegMaxTerm)
		}
		if in.Depth < 0 || in.Depth > RegMaxDepth || in.MaxMatches < 0 || in.MaxMatches > RegMaxMatches {
			return bad("a search goes at most %d levels deep and finds at most %d matches", RegMaxDepth, RegMaxMatches)
		}
	} else if in.Term != "" || in.Depth != 0 || in.MaxMatches != 0 {
		return bad("a term, depth and match limit are for a search")
	}
	return nil
}

// Refused returns the rule that refuses the input's path, or nil.
func (in RegistryInput) Refused() *registryrules.Refusal {
	return registryrules.Check(registryrules.Hive(in.Hive), registryrules.View(in.View), in.Path)
}

// Result line types.
const (
	LineBegin   = "begin"
	LineKey     = "key"
	LineSubkey  = "subkey"
	LineValue   = "value"
	LineMatch   = "match"
	LineXKey    = "xkey"
	LineRefused = "refused"
	LineError   = "error"
	LineEnd     = "end"
)

// States of a listed subkey or an exported key.
const (
	StateOK      = ""
	StateLink    = "link"
	StateDenied  = "denied"
	StateRefused = "refused"
)

// Codes of a RegistryError.
const (
	ErrCodeDenied   = "access_denied"
	ErrCodeNotFound = "not_found"
	ErrCodeRefused  = "refused"
	ErrCodeFailed   = "failed"
)

// RegBegin is the first line: the version, the operation and what was asked.
type RegBegin struct {
	T            string          `json:"t"`
	V            int             `json:"v"`
	Op           string          `json:"op"`
	Hive         string          `json:"hive"`
	View         string          `json:"view"`
	Path         []string        `json:"path"`
	Rules        int             `json:"rules"`
	AgentVersion string          `json:"agentVersion"`
	Arch         string          `json:"arch,omitempty"`
	Cursor       *RegistryCursor `json:"cursor,omitempty"`
}

// RegKey describes the key a list opened.
type RegKey struct {
	T string `json:"t"`
	// Kernel is the kernel's name of the key, such as
	// \REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Vendor.
	Kernel    string `json:"kernel"`
	Subkeys   int    `json:"subkeys"`
	Values    int    `json:"values"`
	LastWrite string `json:"lastWrite,omitempty"`
	ReadAt    string `json:"readAt"`
	// Link is the target of a key that is a link the agent followed.
	Link string `json:"link,omitempty"`
}

// RegSubkey is one subkey of a listed key.
type RegSubkey struct {
	T         string `json:"t"`
	Name      string `json:"name"`
	RawName   string `json:"rawName,omitempty"`
	Subkeys   int    `json:"subkeys"`
	Values    int    `json:"values"`
	LastWrite string `json:"lastWrite,omitempty"`
	State     string `json:"state,omitempty"`
	Target    string `json:"target,omitempty"`
	Rule      string `json:"rule,omitempty"`
	// Label names a loaded user's hive under HKEY_USERS ("Ana Silva").
	Label string `json:"label,omitempty"`
}

// RegValue is one value, as read: raw type and bytes, never expanded. The
// typed fields are the ones ADR-0067's table names; Raw holds the bytes
// themselves for a value read, an export and any odd data.
type RegValue struct {
	T       string `json:"t"`
	Name    string `json:"name"`
	RawName string `json:"rawName,omitempty"`
	Type    uint32 `json:"type"`
	Size    int    `json:"size"`
	Masked  bool   `json:"masked,omitempty"`
	// NoData says the value is larger than a page shows, so its data is not
	// in this line; a value read gets it.
	NoData bool `json:"noData,omitempty"`
	// Denied says Windows denied reading the value.
	Denied  bool     `json:"denied,omitempty"`
	Text    *string  `json:"text,omitempty"`
	Items   []string `json:"items,omitempty"`
	Number  *uint32  `json:"number,omitempty"`
	Decimal string   `json:"decimal,omitempty"`
	Base64  string   `json:"base64,omitempty"`
	Raw     string   `json:"raw,omitempty"`
	Display string   `json:"display,omitempty"`
	Odd     bool     `json:"odd,omitempty"`
	Cut     bool     `json:"cut,omitempty"`
}

// RegMatch is one match of a search: a key's name, a value's name, or a
// value's string data.
type RegMatch struct {
	T    string   `json:"t"`
	Kind string   `json:"kind"`
	Path []string `json:"path"`
	Name string   `json:"name,omitempty"`
	Type uint32   `json:"type,omitempty"`
}

// Kinds of a RegMatch.
const (
	MatchKey       = "key"
	MatchValueName = "valueName"
	MatchData      = "data"
	// MatchLink is a link a search did not follow; Name is its target.
	MatchLink = "link"
)

// SafeText writes text so it can go into JSON and jsonb: a NUL or a byte
// that is not valid text becomes a visible escape.
func SafeText(s string) string {
	if validJSONText(s) {
		return s
	}
	return displayText(s)
}

// RawText is the base64 of s when SafeText had to change it, else empty.
func RawText(s string) string {
	if validJSONText(s) {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// RegXKey is one key of an export, with its values.
type RegXKey struct {
	T         string     `json:"t"`
	Path      []string   `json:"path"`
	State     string     `json:"state,omitempty"`
	Target    string     `json:"target,omitempty"`
	Rule      string     `json:"rule,omitempty"`
	LastWrite string     `json:"lastWrite,omitempty"`
	Values    []RegValue `json:"values,omitempty"`
	// Left says what an export left out of the key's values.
	Left []string `json:"left,omitempty"`
}

// RegRefused says the agent refused a path: the one asked for, the rule and
// the kernel's name where that was what refused it.
type RegRefused struct {
	T      string   `json:"t"`
	Path   []string `json:"path"`
	Rule   string   `json:"rule"`
	Kernel string   `json:"kernel,omitempty"`
}

// RegError says the operation could not read what was asked.
type RegError struct {
	T       string `json:"t"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Bounds that stopped a search or an export.
const (
	StoppedDepth    = "depth"
	StoppedMatches  = "matches"
	StoppedKeys     = "keys"
	StoppedTime     = "time"
	StoppedSize     = "size"
	StoppedExported = "exportKeys"
)

// RegEnd is the last line: the work finished (Complete), or says which
// bound stopped it.
type RegEnd struct {
	T        string `json:"t"`
	Complete bool   `json:"complete"`
	// StoppedBy is one of the Stopped constants for a search or export that
	// did not finish; FirstUnvisited is the first key it did not visit.
	StoppedBy      string   `json:"stoppedBy,omitempty"`
	FirstUnvisited []string `json:"firstUnvisited,omitempty"`
	Visited        int      `json:"visited,omitempty"`
	Matches        int      `json:"matches,omitempty"`
	// MoreSubkeys and MoreValues say a list page ended before the key's
	// subkeys or values did; the cursor continues after NextSubkey and
	// NextValue.
	MoreSubkeys bool   `json:"moreSubkeys,omitempty"`
	MoreValues  bool   `json:"moreValues,omitempty"`
	NextSubkey  string `json:"nextSubkey,omitempty"`
	NextValue   string `json:"nextValue,omitempty"`
	ElapsedMS   int64  `json:"elapsedMs"`
}

// RegistryResult is a result decoded from its lines.
type RegistryResult struct {
	Begin    RegBegin
	Key      *RegKey
	Subkeys  []RegSubkey
	Values   []RegValue
	Matches  []RegMatch
	XKeys    []RegXKey
	Refused  []RegRefused
	Errors   []RegError
	End      *RegEnd
	rawLines int
}

// ErrRegistryResult is a result that does not decode.
var ErrRegistryResult = errors.New("agentproto: the registry result is not valid")

// SplitResultLines splits a result file into its whole lines. A last line
// without a line break was cut short and is dropped. Empty lines are
// skipped.
func SplitResultLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			break
		}
		line := bytes.TrimRight(b[:i], "\r")
		b = b[i+1:]
		if len(bytes.TrimSpace(line)) > 0 {
			out = append(out, line)
		}
	}
	return out
}

// ValidRegistryText reports whether a line holds no NUL and no lone
// surrogate, as an escape or as text: jsonb refuses the first and does not
// take the second.
func ValidRegistryText(line []byte) bool {
	if !utf8.Valid(line) || bytes.IndexByte(line, 0) >= 0 {
		return false
	}
	for i := 0; i+1 < len(line); i++ {
		if line[i] != '\\' {
			continue
		}
		if line[i+1] != 'u' {
			i++ // skip the escaped character, which may be another backslash
			continue
		}
		if i+6 > len(line) {
			return false
		}
		u, err := strconv.ParseUint(string(line[i+2:i+6]), 16, 16)
		if err != nil || u == 0 {
			return false
		}
		switch {
		case u >= 0xD800 && u < 0xDC00:
			// A high surrogate must be followed by \uDC00-\uDFFF.
			if i+12 > len(line) || line[i+6] != '\\' || line[i+7] != 'u' {
				return false
			}
			lo, err := strconv.ParseUint(string(line[i+8:i+12]), 16, 16)
			if err != nil || lo < 0xDC00 || lo > 0xDFFF {
				return false
			}
			i += 11
			continue
		case u >= 0xDC00 && u <= 0xDFFF:
			return false
		}
		i += 5
	}
	return true
}

func strictLine(line []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("more than one document on a line")
	}
	return nil
}

// ParseRegistryLines decodes a result's lines strictly. The first is the
// begin line and, for a finished result, the last is end; a result without
// end is partial (Result.End is nil).
func ParseRegistryLines(lines [][]byte) (*RegistryResult, error) {
	bad := func(i int, err error) error { return fmt.Errorf("%w: line %d: %w", ErrRegistryResult, i+1, err) }
	if len(lines) == 0 {
		return nil, fmt.Errorf("%w: it is empty", ErrRegistryResult)
	}
	r := &RegistryResult{rawLines: len(lines)}
	for i, line := range lines {
		if !ValidRegistryText(line) {
			return nil, bad(i, errors.New("it holds a NUL or a lone surrogate"))
		}
		var head struct {
			T string `json:"t"`
		}
		if err := json.Unmarshal(line, &head); err != nil {
			return nil, bad(i, err)
		}
		if (i == 0) != (head.T == LineBegin) {
			return nil, bad(i, errors.New("the begin line is first, and only first"))
		}
		if r.End != nil {
			return nil, bad(i, errors.New("a line after the end"))
		}
		var err error
		switch head.T {
		case LineBegin:
			err = strictLine(line, &r.Begin)
		case LineKey:
			var k RegKey
			if err = strictLine(line, &k); err == nil {
				if r.Key != nil {
					err = errors.New("two key lines")
				}
				r.Key = &k
			}
		case LineSubkey:
			var k RegSubkey
			if err = strictLine(line, &k); err == nil {
				r.Subkeys = append(r.Subkeys, k)
			}
		case LineValue:
			var v RegValue
			if err = strictLine(line, &v); err == nil {
				r.Values = append(r.Values, v)
			}
		case LineMatch:
			var m RegMatch
			if err = strictLine(line, &m); err == nil {
				r.Matches = append(r.Matches, m)
			}
		case LineXKey:
			var k RegXKey
			if err = strictLine(line, &k); err == nil {
				r.XKeys = append(r.XKeys, k)
			}
		case LineRefused:
			var f RegRefused
			if err = strictLine(line, &f); err == nil {
				r.Refused = append(r.Refused, f)
			}
		case LineError:
			var e RegError
			if err = strictLine(line, &e); err == nil {
				r.Errors = append(r.Errors, e)
			}
		case LineEnd:
			var e RegEnd
			if err = strictLine(line, &e); err == nil {
				r.End = &e
			}
		default:
			err = fmt.Errorf("line type %q is not known", head.T)
		}
		if err != nil {
			return nil, bad(i, err)
		}
	}
	return r, nil
}

// Lines is how many lines the result had.
func (r *RegistryResult) Lines() int { return r.rawLines }

// EncodeRegValue makes a value's line from what the registry holds: its
// name, type and raw bytes. A page shows data up to RegValuePageBytes; with
// withRaw (a value read, an export) the bytes are included too, up to
// limit, cut and marked beyond it. masked says the data is not given at all.
// A name or data that cannot go into JSON as it is (a NUL, a lone
// surrogate, no terminator, an odd length) is sent as raw bytes with a
// display text, and marked odd, so that no one saves bytes they did not see.
func EncodeRegValue(name string, typ uint32, data []byte, masked, withRaw bool, limit int) RegValue {
	v := RegValue{T: LineValue, Name: name, Type: typ, Size: len(data), Masked: masked}
	if !validJSONText(name) {
		v.Odd = true
		v.RawName = base64.StdEncoding.EncodeToString([]byte(name))
		v.Name = displayText(name)
	}
	if masked {
		return v
	}
	if !withRaw && len(data) > RegValuePageBytes {
		v.NoData = true
		return v
	}
	if len(data) > limit {
		data, v.Cut = data[:limit], true
	}
	if withRaw || v.Cut {
		v.Raw = base64.StdEncoding.EncodeToString(data)
	}
	if v.Cut {
		return v
	}
	switch typ {
	case registryrules.TypeSZ, registryrules.TypeExpandSZ:
		if s, ok := decodeSZ(data); ok {
			v.Text = &s
			return v
		}
	case registryrules.TypeMultiSZ:
		if items, ok := decodeMultiSZ(data); ok {
			v.Items = items
			if v.Items == nil {
				v.Items = []string{}
			}
			return v
		}
	case registryrules.TypeDWord:
		if len(data) == 4 {
			n := binary.LittleEndian.Uint32(data)
			v.Number = &n
			return v
		}
	case registryrules.TypeQWord:
		if len(data) == 8 {
			v.Decimal = strconv.FormatUint(binary.LittleEndian.Uint64(data), 10)
			return v
		}
	default:
		v.Base64 = base64.StdEncoding.EncodeToString(data)
		return v
	}
	// Odd: the type is a text or number type whose bytes are not one.
	v.Odd = true
	v.Raw = base64.StdEncoding.EncodeToString(data)
	if typ == registryrules.TypeSZ || typ == registryrules.TypeExpandSZ || typ == registryrules.TypeMultiSZ {
		v.Display = displayUTF16(data)
	}
	return v
}

// validJSONText reports whether s can be sent in JSON and kept in jsonb as
// it is: valid UTF-8, no NUL.
func validJSONText(s string) bool { return utf8.ValidString(s) && !strings.ContainsRune(s, 0) }

// displayText writes a name with each character jsonb cannot keep as a
// visible escape.
func displayText(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, n := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02X`, s[0])
		case r == 0:
			b.WriteString(`\0`)
		default:
			b.WriteRune(r)
		}
		s = s[n:]
	}
	return b.String()
}

func utf16Units(data []byte) []uint16 {
	u := make([]uint16, len(data)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	return u
}

// loneSurrogate reports whether units hold a surrogate with no partner.
func loneSurrogate(units []uint16) bool {
	for i := 0; i < len(units); i++ {
		switch u := units[i]; {
		case u >= 0xD800 && u < 0xDC00:
			if i+1 >= len(units) || units[i+1] < 0xDC00 || units[i+1] > 0xDFFF {
				return true
			}
			i++
		case u >= 0xDC00 && u <= 0xDFFF:
			return true
		}
	}
	return false
}

// decodeSZ reads REG_SZ data: UTF-16LE with one terminating NUL, which is
// dropped, and no other NUL.
func decodeSZ(data []byte) (string, bool) {
	if len(data)%2 != 0 || len(data) < 2 {
		return "", false
	}
	u := utf16Units(data)
	if u[len(u)-1] != 0 {
		return "", false
	}
	u = u[:len(u)-1]
	for _, c := range u {
		if c == 0 {
			return "", false
		}
	}
	if loneSurrogate(u) {
		return "", false
	}
	return string(utf16.Decode(u)), true
}

// decodeMultiSZ reads REG_MULTI_SZ data: strings each ended by a NUL, and a
// last NUL; no empty item.
func decodeMultiSZ(data []byte) ([]string, bool) {
	if len(data)%2 != 0 {
		return nil, false
	}
	if len(data) == 0 {
		return nil, true
	}
	u := utf16Units(data)
	if u[len(u)-1] != 0 {
		return nil, false
	}
	u = u[:len(u)-1]
	if len(u) == 0 {
		return nil, true
	}
	if u[len(u)-1] != 0 { // only one terminator: a single item with none for the list
		return nil, false
	}
	u = u[:len(u)-1]
	if len(u) == 0 {
		return nil, true // an empty list: two NULs
	}
	if loneSurrogate(u) {
		return nil, false
	}
	var items []string
	start := 0
	for i := 0; i <= len(u); i++ {
		if i == len(u) || u[i] == 0 {
			if i == start {
				return nil, false // an empty item
			}
			items = append(items, string(utf16.Decode(u[start:i])))
			start = i + 1
		}
	}
	return items, true
}

// displayUTF16 shows UTF-16LE data with a visible escape for each character
// that cannot be shown: NUL, a lone surrogate, and a trailing odd byte.
func displayUTF16(data []byte) string {
	var b strings.Builder
	u := utf16Units(data)
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch {
		case c == 0:
			b.WriteString(`\0`)
		case c >= 0xD800 && c < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] <= 0xDFFF:
			b.WriteRune(utf16.DecodeRune(rune(c), rune(u[i+1])))
			i++
		case c >= 0xD800 && c <= 0xDFFF:
			fmt.Fprintf(&b, `\u%04X`, c)
		default:
			b.WriteRune(rune(c))
		}
	}
	if len(data)%2 == 1 {
		fmt.Fprintf(&b, `\x%02X`, data[len(data)-1])
	}
	return b.String()
}

// RegValueBytes returns the raw bytes of a value line decoded from a result:
// Raw where there is one, otherwise rebuilt from the typed fields. ok is
// false for a value whose data is not in the line (masked, or too large).
func RegValueBytes(v RegValue) ([]byte, bool) {
	if v.Masked || v.NoData {
		return nil, false
	}
	if v.Raw != "" {
		b, err := base64.StdEncoding.DecodeString(v.Raw)
		return b, err == nil
	}
	switch {
	case v.Text != nil:
		return encodeUTF16(*v.Text + "\x00"), true
	case v.Items != nil:
		var s strings.Builder
		for _, it := range v.Items {
			s.WriteString(it + "\x00")
		}
		s.WriteString("\x00")
		if len(v.Items) == 0 {
			return encodeUTF16("\x00\x00"), true
		}
		return encodeUTF16(s.String()), true
	case v.Number != nil:
		return binary.LittleEndian.AppendUint32(nil, *v.Number), true
	case v.Decimal != "":
		n, err := strconv.ParseUint(v.Decimal, 10, 64)
		return binary.LittleEndian.AppendUint64(nil, n), err == nil
	case v.Base64 != "":
		b, err := base64.StdEncoding.DecodeString(v.Base64)
		return b, err == nil
	}
	return []byte{}, v.Size == 0
}

func encodeUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return b
}
