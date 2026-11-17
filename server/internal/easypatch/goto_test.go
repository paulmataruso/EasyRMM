package easypatch

import (
	"testing"

	"github.com/google/uuid"
)

func TestEasyPatchPage(t *testing.T) {
	endpoint, org := uuid.MustParse("0b6f4f3e-8a43-4bde-9d2a-2f0c1d7f5a10"), uuid.MustParse("6d1c2b9a-1f0e-4c5d-8b7a-3e2d1c0b9a87")
	for _, c := range []struct {
		name, base string
		page       goPage
		want       string
	}{
		{"endpoint", "https://patch.example.com", goPage{endpointID: endpoint, tab: "history"},
			"https://patch.example.com/endpoints/" + endpoint.String() + "?from=easyrmm&tab=history"},
		{"overview", "https://patch.example.com", goPage{endpointID: endpoint, tab: "overview"},
			"https://patch.example.com/endpoints/" + endpoint.String() + "?from=easyrmm"},
		{"tab injection", "https://patch.example.com", goPage{endpointID: endpoint, tab: "updates&from=x"},
			"https://patch.example.com/endpoints/" + endpoint.String() + "?from=easyrmm"},
		{"search", "https://patch.example.com", goPage{search: "Front desk & co"},
			"https://patch.example.com/endpoints?from=easyrmm&search=Front+desk+%26+co"},
		{"under a path", "https://example.com/easypatch", goPage{organization: org},
			"https://example.com/easypatch/organizations/" + org.String() + "?from=easyrmm"},
		{"organizations", "https://patch.example.com", goPage{orgs: true}, "https://patch.example.com/organizations?from=easyrmm"},
		{"home", "https://patch.example.com", goPage{}, "https://patch.example.com/?from=easyrmm"},
	} {
		if got := easyPatchPage(c.base, c.page); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
