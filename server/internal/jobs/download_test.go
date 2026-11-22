package jobs

import (
	"strings"
	"testing"
)

// TestFileName keeps names in downloads and archives to letters, digits,
// '-', '_' and '.', never a leading dot or two together (ADR-0064).
func TestFileName(t *testing.T) {
	for in, want := range map[string]string{
		"SRV-01":         "SRV-01",
		"../HQ 01":       "__HQ_01",
		"srv..01":        "srv._01",
		".hidden":        "hidden",
		"a/b\\c:d":       "a_b_c_d",
		"Ünïcode":        "_n_code",
		"":               "device",
		"...":            "_.",
		"name.with.dots": "name.with.dots",
	} {
		if got := fileName(in); got != want {
			t.Errorf("fileName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := fileName(strings.Repeat("x", 100)); got != strings.Repeat("x", 64) {
		t.Errorf("a long name: %q", got)
	}
}
