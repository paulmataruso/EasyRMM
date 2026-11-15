package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func TestPathID(t *testing.T) {
	want := uuid.New()
	var got uuid.UUID
	var gotErr error
	mux := http.NewServeMux()
	mux.HandleFunc("GET /things/{id}", func(_ http.ResponseWriter, r *http.Request) {
		got, gotErr = PathID(r)
	})
	mux.HandleFunc("GET /others/{other}", func(_ http.ResponseWriter, r *http.Request) {
		got, gotErr = PathUUID(r, "other")
	})

	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/things/"+want.String(), nil))
	if gotErr != nil || got != want {
		t.Fatalf("PathID = %v, %v", got, gotErr)
	}
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/things/not-a-uuid", nil))
	if !errors.Is(gotErr, apperr.ErrNotFound) || got != uuid.Nil {
		t.Fatalf("malformed PathID = %v, %v; want not found", got, gotErr)
	}
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/others/"+want.String(), nil))
	if gotErr != nil || got != want {
		t.Fatalf("PathUUID = %v, %v", got, gotErr)
	}
}

func TestQueryID(t *testing.T) {
	id := uuid.New()
	got, err := QueryID(httptest.NewRequest(http.MethodGet, "/?org="+id.String(), nil), "org")
	if err != nil || got != id {
		t.Fatalf("QueryID = %v, %v", got, err)
	}
	got, err = QueryID(httptest.NewRequest(http.MethodGet, "/", nil), "org")
	if err != nil || got != uuid.Nil {
		t.Fatalf("absent QueryID = %v, %v", got, err)
	}
	_, err = QueryID(httptest.NewRequest(http.MethodGet, "/?org=xyz", nil), "org")
	ae, ok := apperr.As(err)
	if !ok || ae.Kind != apperr.KindInvalid || ae.Fields["org"] == "" {
		t.Fatalf("malformed QueryID err = %v", err)
	}
}

func TestQueryInt(t *testing.T) {
	cases := []struct {
		query string
		want  int64
		ok    bool
	}{
		{"", 50, true},
		{"limit=1", 1, true},
		{"limit=200", 200, true},
		{"limit=0", 0, false},
		{"limit=201", 0, false},
		{"limit=-5", 0, false},
		{"limit=ten", 0, false},
		{"limit=99999999999999999999", 0, false},
	}
	for _, c := range cases {
		got, err := QueryInt(httptest.NewRequest(http.MethodGet, "/?"+c.query, nil), "limit", 50, 1, 200)
		if c.ok {
			if err != nil || got != c.want {
				t.Errorf("%q: got %d, %v; want %d", c.query, got, err, c.want)
			}
			continue
		}
		ae, ok := apperr.As(err)
		if !ok || ae.Fields["limit"] != "must be a whole number between 1 and 200" {
			t.Errorf("%q: err = %v", c.query, err)
		}
	}
}
