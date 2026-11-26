package winmod

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

// Default length bounds.
const (
	defaultNameMax = 256
	defaultPathMax = 1024
	defaultTextMax = 1024
)

var (
	namePattern = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._\-@$']*$`)
	pathPattern = regexp.MustCompile(`^[A-Za-z]:\\`)
	sidPattern  = regexp.MustCompile(`^S-1-\d{1,10}(-\d{1,10}){1,15}$`)
)

// Checked is a request's parameters after validation.
type Checked struct {
	// Params are the parameters without secrets, in the form the job keeps.
	Params json.RawMessage
	// Secrets are the secret parameters' values, by name.
	Secrets map[string]string
	// Audit is what the audit row records: each plain value as it is, each
	// sensitive or secret one as its length and SHA-256 (a secret as its
	// presence only).
	Audit map[string]any
	// Subject is the value of the action's confirmation subject.
	Subject string
}

// Validate checks a request's parameters against the action's schema:
// every name declared, required ones present, each value of its type and
// within its bounds. Nothing is escaped; a value that does not match is
// refused with the reason.
func (a Action) Validate(raw json.RawMessage) (*Checked, error) {
	in := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := dec.Decode(&in); err != nil || dec.More() {
			return nil, apperr.Invalid("params", "The parameters must be a JSON object.")
		}
	}
	f := apperr.Fields{}
	declared := map[string]bool{}
	for _, p := range a.Params {
		declared[p.Name] = true
	}
	for k := range in {
		f.Check(declared[k], "params."+k, "This action has no parameter of this name.")
	}
	out := &Checked{Secrets: map[string]string{}, Audit: map[string]any{}}
	plain := map[string]any{}
	for _, p := range a.Params {
		v, present := in[p.Name]
		field := "params." + p.Name
		if !present || v == nil {
			f.Check(!p.Required, field, "This parameter is required.")
			continue
		}
		val, msg := p.check(v)
		if msg != "" {
			f.Add(field, msg)
			continue
		}
		switch {
		case p.Secret:
			s, _ := val.(string)
			out.Secrets[p.Name] = s
			out.Audit[p.Name] = "(secret)"
			continue
		case p.Sensitive:
			out.Audit[p.Name] = lengthAndHash(val)
		default:
			out.Audit[p.Name] = val
		}
		plain[p.Name] = val
		if p.Name == a.Subject {
			out.Subject, _ = val.(string)
		}
	}
	if a.Subject != "" && out.Subject == "" {
		if s, ok := out.Secrets[a.Subject]; ok {
			out.Subject = s
		}
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	b, err := MarshalParams(plain)
	if err != nil {
		return nil, err
	}
	out.Params = b
	return out, nil
}

func lengthAndHash(v any) map[string]any {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return map[string]any{"length": utf8.RuneCount(b), "sha256": hex.EncodeToString(sum[:])}
}

// check validates one value and returns it in its canonical form, or why not.
func (p Param) check(v any) (any, string) {
	str := func(def int) (string, string) {
		s, ok := v.(string)
		if !ok {
			return "", "This must be text."
		}
		maxLen := p.Max
		if maxLen == 0 {
			maxLen = def
		}
		n := utf8.RuneCountInString(s)
		switch {
		case n < max(p.Min, 1):
			return "", "This is too short."
		case n > maxLen:
			return "", "This is too long."
		case !utf8.ValidString(s) || strings.IndexFunc(s, unicode.IsControl) >= 0:
			return "", "This holds a character that is not allowed."
		}
		return s, ""
	}
	switch p.Type {
	case Name:
		s, msg := str(defaultNameMax)
		if msg == "" && !namePattern.MatchString(s) {
			msg = "Use letters, digits, spaces and . _ - @ $ ' only."
		}
		return s, msg
	case Path:
		s, msg := str(defaultPathMax)
		if msg != "" {
			return s, msg
		}
		if !pathPattern.MatchString(s) {
			return s, "Use an absolute path such as C:\\Folder."
		}
		for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '\\' || r == '/' }) {
			if seg == ".." || seg == "." {
				return s, "The path must not contain . or .. parts."
			}
		}
		if strings.ContainsAny(s, "/<>\"|?*") || strings.Contains(s[2:], ":") {
			return s, "The path holds a character that is not allowed."
		}
		return s, ""
	case GUID:
		s, ok := v.(string)
		if !ok {
			return nil, "This must be a GUID."
		}
		id, err := uuid.Parse(strings.Trim(s, "{}"))
		if err != nil || len(strings.Trim(s, "{}")) != 36 {
			return nil, "This must be a GUID."
		}
		return id.String(), ""
	case SID:
		s, ok := v.(string)
		if !ok || !sidPattern.MatchString(s) {
			return nil, "This must be a security identifier such as S-1-5-21-1-2-3-1001."
		}
		return s, ""
	case Int:
		n, ok := v.(json.Number)
		if !ok {
			return nil, "This must be a whole number."
		}
		i, err := n.Int64()
		if err != nil || i < int64(p.Min) || (p.Max != 0 && i > int64(p.Max)) || i > math.MaxInt32 {
			return nil, "This number is out of range."
		}
		return i, ""
	case Bool:
		b, ok := v.(bool)
		if !ok {
			return nil, "This must be true or false."
		}
		return b, ""
	case Enum:
		s, ok := v.(string)
		if !ok || !slices.Contains(p.Values, s) {
			return nil, "Use one of: " + strings.Join(p.Values, ", ") + "."
		}
		return s, ""
	case Text:
		return str(defaultTextMax)
	}
	return nil, "This parameter's type is not known."
}
