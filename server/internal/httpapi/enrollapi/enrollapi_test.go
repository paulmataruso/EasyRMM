package enrollapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

func TestDownloadsDescribeEveryAddress(t *testing.T) {
	ca := &Authority{Fingerprint: "AB:CD", URL: "/api/agent/v1/ca.pem"}
	a := New(nil, &agents.Builds{}, "https://rmm.example.com/", []Address{
		{URL: "https://rmm.example.com"}, {URL: "https://203.0.113.10", Pin: "sha256//x"},
	}, ca)
	var got downloads
	for _, o := range []*httpapi.Origin{nil, {Console: "https://203.0.113.10"}} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/agent-downloads", nil)
		if o != nil {
			r = httpapi.WithOrigin(r, *o)
		}
		w := httptest.NewRecorder()
		if err := a.downloads(w, r); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		want := "https://rmm.example.com"
		if o != nil {
			want = o.Console
		}
		if got.Current != want || got.ServerURL != "https://rmm.example.com" || len(got.Addresses) != 2 ||
			got.Addresses[1].Pin != "sha256//x" || got.CertificateAuthority == nil || got.CertificateAuthority.Fingerprint != "AB:CD" {
			t.Errorf("downloads = %+v", got)
		}
	}
	// Without addresses, the public URL is the only one, unpinned.
	b := New(nil, &agents.Builds{}, "https://rmm.example.com", nil, nil)
	if len(b.addresses) != 1 || b.addresses[0].URL != "https://rmm.example.com" || b.ca != nil {
		t.Errorf("default addresses = %+v", b.addresses)
	}
}

// With a dev scope set, the console's downloads, tied to no organization,
// are the stable builds; without one, the server's.
func TestDownloadsFollowTheDevScope(t *testing.T) {
	load := func(body string) *agents.Builds {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "easyrmm-agent-linux-amd64"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		b, err := agents.LoadBuilds(dir)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	fresh, stable := load("new build"), load("stable build")
	svc := agents.New(nil, nil, nil, nil)
	svc.SetUpdates(fresh, nil)
	a := New(svc, fresh, "https://rmm.example.com", nil, nil)
	sums := func() []agents.Build {
		w := httptest.NewRecorder()
		if err := a.downloads(w, httptest.NewRequest(http.MethodGet, "/api/v1/agent-downloads", nil)); err != nil {
			t.Fatal(err)
		}
		var got downloads
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got.Items
	}
	if got := sums(); len(got) != 1 || got[0].SHA256 != fresh.List()[0].SHA256 {
		t.Errorf("no scope: %+v", got)
	}
	t.Cleanup(devscope.Set(uuid.New()))
	if got := sums(); len(got) != 0 {
		t.Errorf("scope set, no stable builds loaded, offered %+v", got)
	}
	svc.SetStable(stable)
	if got := sums(); len(got) != 1 || got[0].SHA256 != stable.List()[0].SHA256 {
		t.Errorf("scope set: %+v, want the stable build", got)
	}
}
