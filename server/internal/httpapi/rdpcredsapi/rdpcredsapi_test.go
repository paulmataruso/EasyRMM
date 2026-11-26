package rdpcredsapi

import (
	"encoding/json"
	"testing"
)

func TestSecretBytesDecodesLikeEncodingJSON(t *testing.T) {
	for _, want := range []string{"", "plain", "q\"uote", `back\slash`, "a/b", "tab\tnl\n\r\b\f\x01", "é世", "\U0001F600", " ", "</script>&"} {
		raw, _ := json.Marshal(want)
		var got secretBytes
		if err := got.UnmarshalJSON(raw); err != nil || string(got) != want {
			t.Errorf("%s: %q, %v", raw, got, err)
		}
	}
	// Escapes encoding/json writes in other forms.
	for raw, want := range map[string]string{
		`"A\/😀"`:    "A/\U0001F600",
		`"😀"`:       "\U0001F600",
		`"\ud83dx"`: "�x", // a lone surrogate
	} {
		var got secretBytes
		if err := got.UnmarshalJSON([]byte(raw)); err != nil || string(got) != want {
			t.Errorf("%s: %q, %v", raw, got, err)
		}
		var std string
		if err := json.Unmarshal([]byte(raw), &std); err != nil || std != want {
			t.Errorf("encoding/json disagrees on %s: %q", raw, std)
		}
	}
	for _, raw := range []string{`5`, `null`, `{}`, `"`, `"abc`, `"\"`, `"\x"`, `"\u12"`, `"\u12zz"`, `[]`} {
		var got secretBytes
		if err := got.UnmarshalJSON([]byte(raw)); err == nil {
			t.Errorf("%s accepted as %q", raw, got)
		}
	}
}
