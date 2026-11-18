package enrollapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/agents"
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
