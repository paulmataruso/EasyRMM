package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) ErrorDetail {
	t.Helper()
	var body ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding error body %q: %v", rec.Body.String(), err)
	}
	return body.Error
}

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusCreated, map[string]string{"html": "<script>"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache control = %q", cc)
	}
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("HTML not escaped: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	WriteJSON(rec, http.StatusNoContent, nil)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("nil body: status %d body %q", rec.Code, rec.Body.String())
	}
}

func TestWriteErrorAPIError(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	WriteError(rec, req, Validation(map[string]string{"name": "required"}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d", rec.Code)
	}
	d := decodeError(t, rec)
	if d.Code != "validation_failed" || d.Fields["name"] != "required" {
		t.Fatalf("detail = %+v", d)
	}

	// Wrapped API errors are still recognized.
	rec = httptest.NewRecorder()
	WriteError(rec, req, errors.Join(errors.New("context"), ErrForbidden))
	if rec.Code != http.StatusForbidden || decodeError(t, rec).Code != "forbidden" {
		t.Fatalf("wrapped: %d %s", rec.Code, rec.Body.String())
	}
}

func TestWriteErrorAppErrKinds(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	cases := []struct {
		err    error
		status int
		code   string
	}{
		{apperr.Invalid("email", "bad"), http.StatusUnprocessableEntity, "validation_failed"},
		{apperr.NotFound(), http.StatusNotFound, "not_found"},
		{apperr.Forbidden(), http.StatusForbidden, "forbidden"},
		{apperr.Conflict("busy", "It is busy."), http.StatusConflict, "busy"},
		{apperr.Unavailable("remote_unavailable", "Down."), http.StatusServiceUnavailable, "remote_unavailable"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		WriteError(rec, req, c.err)
		if rec.Code != c.status {
			t.Errorf("%v: status %d, want %d", c.err, rec.Code, c.status)
		}
		if got := decodeError(t, rec).Code; got != c.code {
			t.Errorf("%v: code %q, want %q", c.err, got, c.code)
		}
	}

	// An apperr with an unknown kind is an internal error.
	rec := httptest.NewRecorder()
	WriteError(rec, req, &apperr.Error{Kind: 99, Code: "weird", Message: "secret detail"})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "secret detail") {
		t.Fatalf("unknown kind: %d %s", rec.Code, rec.Body.String())
	}
}

func TestWriteErrorUnknownIsGeneric(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	req := httptest.NewRequest(http.MethodPost, "/api/thing", nil)
	req = req.WithContext(context.WithValue(req.Context(), loggerKey{}, log))
	rec := httptest.NewRecorder()
	WriteError(rec, req, errors.New("pq: password authentication failed for user secret"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	d := decodeError(t, rec)
	if d.Code != "internal_error" || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("leaked detail: %s", rec.Body.String())
	}
	if !strings.Contains(logs.String(), "password authentication failed") {
		t.Fatalf("error was not logged: %s", logs.String())
	}
}

func TestWriteErrorClientGone(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), loggerKey{}, log))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil).WithContext(ctx)
	cancel()
	rec := httptest.NewRecorder()
	WriteError(rec, req, fmt.Errorf("auth: loading roles: %w", context.Canceled))
	if rec.Code != StatusClientClosedRequest || strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "canceled by the client") {
		t.Errorf("canceled request: %d, logged %q", rec.Code, logs.String())
	}
	// A cancellation the client did not cause is still a server failure.
	logs.Reset()
	rec = httptest.NewRecorder()
	WriteError(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sites", nil).WithContext(context.WithValue(context.Background(), loggerKey{}, log)), context.Canceled)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(logs.String(), "level=ERROR") {
		t.Errorf("server-side cancellation: %d, logged %q", rec.Code, logs.String())
	}
}

func TestErrorString(t *testing.T) {
	if got := Conflict("dup", "Duplicate.").Error(); got != "dup: Duplicate." {
		t.Fatalf("Error() = %q", got)
	}
	if e := BadRequest("nope"); e.Status != http.StatusBadRequest || e.Code != "bad_request" {
		t.Fatalf("BadRequest = %+v", e)
	}
}

type sample struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func decodeReq(body, contentType string) (*httptest.ResponseRecorder, *http.Request) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return httptest.NewRecorder(), req
}

func TestDecodeJSON(t *testing.T) {
	cases := []struct {
		name, body, ct string
		status         int
		code           string
		field          string
	}{
		{"wrong content type", `{"name":"x"}`, "text/plain", http.StatusUnsupportedMediaType, "unsupported_media_type", ""},
		{"missing content type", `{"name":"x"}`, "", http.StatusUnsupportedMediaType, "unsupported_media_type", ""},
		{"malformed content type", `{"name":"x"}`, "application/json; =", http.StatusUnsupportedMediaType, "unsupported_media_type", ""},
		{"empty body", ``, "application/json", http.StatusBadRequest, "bad_request", ""},
		{"invalid json", `{"name":}`, "application/json", http.StatusBadRequest, "bad_request", ""},
		{"unexpected eof", `{"name":"x"`, "application/json", http.StatusBadRequest, "bad_request", ""},
		{"wrong type", `{"count":"seven"}`, "application/json", http.StatusUnprocessableEntity, "validation_failed", "count"},
		{"string instead of object", `"seven"`, "application/json", http.StatusBadRequest, "bad_request", ""},
		{"unknown field", `{"name":"x","admin":true}`, "application/json", http.StatusUnprocessableEntity, "validation_failed", "admin"},
		{"trailing value", `{"name":"x"} {"name":"y"}`, "application/json", http.StatusBadRequest, "bad_request", ""},
		{"array instead of object", `[1,2]`, "application/json", http.StatusBadRequest, "bad_request", ""},
		{"too large", `{"name":"` + strings.Repeat("a", MaxJSONBody) + `"}`, "application/json", http.StatusRequestEntityTooLarge, "body_too_large", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, req := decodeReq(c.body, c.ct)
			var dst sample
			err := DecodeJSON(rec, req, &dst)
			var apiErr *Error
			if !errors.As(err, &apiErr) {
				t.Fatalf("err = %v, want *Error", err)
			}
			if apiErr.Status != c.status || apiErr.Code != c.code {
				t.Fatalf("got %d %s (%s), want %d %s", apiErr.Status, apiErr.Code, apiErr.Message, c.status, c.code)
			}
			if c.field != "" {
				if _, ok := apiErr.Fields[c.field]; !ok {
					t.Fatalf("fields = %v, want %q", apiErr.Fields, c.field)
				}
			}
		})
	}
}

func TestDecodeJSONUnreadableBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", failingReader{})
	req.Header.Set("Content-Type", "application/json")
	var dst sample
	err := DecodeJSON(httptest.NewRecorder(), req, &dst)
	var apiErr *Error
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusBadRequest || !strings.Contains(apiErr.Message, "could not be read") {
		t.Fatalf("err = %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func TestDecodeJSONSuccess(t *testing.T) {
	rec, req := decodeReq(`{"name":"box","count":3}`+"\n", "application/json; charset=utf-8")
	var dst sample
	if err := DecodeJSON(rec, req, &dst); err != nil {
		t.Fatal(err)
	}
	if dst.Name != "box" || dst.Count != 3 {
		t.Fatalf("dst = %+v", dst)
	}
}

func TestHandle(t *testing.T) {
	h := Handle(func(w http.ResponseWriter, _ *http.Request) error {
		return ErrNotFound
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}

	ok := Handle(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusAccepted)
		return nil
	})
	rec = httptest.NewRecorder()
	ok.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestLoggerFromDefault(t *testing.T) {
	if LoggerFrom(context.Background()) != slog.Default() {
		t.Fatal("expected the default logger")
	}
}

func TestLogSafe(t *testing.T) {
	for in, want := range map[string]string{
		"/api/v1/devices":            "/api/v1/devices",
		"/a\nlevel=ERROR msg=forged": `/a\nlevel=ERROR msg=forged`,
		"/a\r\nb":                    `/a\r\nb`,
		"":                           "",
	} {
		if got := LogSafe(in); got != want {
			t.Errorf("LogSafe(%q) = %q, want %q", in, got, want)
		}
	}
}
