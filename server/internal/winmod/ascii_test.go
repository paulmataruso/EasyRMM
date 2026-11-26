package winmod

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalParamsIsASCIIAndRoundTrips(t *testing.T) {
	in := map[string]any{
		"name":  "Zo\u00eb \u2603 \U0001F600 \u65e5\u672c\u8a9e \u202e",
		"quote": "a\"b'c`d$(e)\nf\\g<h>&i",
		"n":     3,
	}
	b, err := MarshalParams(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range b {
		if c >= 0x80 {
			t.Fatalf("a non-ASCII byte in %s", b)
		}
	}
	if !bytes.Contains(b, []byte("\\ud83d\\ude00")) {
		t.Fatalf("an astral character must be a surrogate pair: %s", b)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"name", "quote"} {
		if out[k] != in[k] {
			t.Fatalf("%s changed: %q", k, out[k])
		}
	}
}
