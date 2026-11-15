// Package agentapi serves the EasyRMM agent (ADR-0015): enrollment with a
// deployment token, signed heartbeats, MeshAgent delivery, and the agent
// downloads and Linux installer.
//
// These routes are reached without a browser session and without CSRF
// checks; enrollment is authorized by the token, everything else by the
// device's Ed25519 signature.
package agentapi

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"text/template"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

//go:embed install.sh.tmpl
var installTemplate string

var installScript = template.Must(template.New("install.sh").Parse(installTemplate))

// API serves the agent routes.
type API struct {
	svc     *agents.Service
	builds  *agents.Builds
	install []byte
	log     *slog.Logger
}

// New builds the API. server is the public URL agents use.
func New(svc *agents.Service, builds *agents.Builds, server string, log *slog.Logger) (*API, error) {
	server = strings.TrimSuffix(server, "/")
	if strings.ContainsAny(server, "'\\\n\r\"$`") {
		return nil, errors.New("agentapi: the public URL cannot be put in the installer")
	}
	var buf bytes.Buffer
	if err := installScript.Execute(&buf, struct {
		Server string
		HTTPS  bool
	}{server, strings.HasPrefix(server, "https://")}); err != nil {
		return nil, err
	}
	return &API{svc: svc, builds: builds, install: buf.Bytes(), log: log}, nil
}

// Handler returns the handler for everything under agentproto.PathPrefix.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+agentproto.PathEnroll, httpapi.Handle(a.enroll))
	mux.Handle("POST "+agentproto.PathHeartbeat, httpapi.Handle(a.signed(a.heartbeat)))
	mux.Handle("GET "+agentproto.PathMeshAgent, httpapi.Handle(a.signed(a.meshAgent)))
	mux.Handle("GET "+agentproto.PathMeshSettings, httpapi.Handle(a.signed(a.meshSettings)))
	mux.Handle("GET /api/agent/v1/install.sh", httpapi.Handle(a.installer))
	mux.Handle("GET /api/agent/v1/download/{file}", httpapi.Handle(a.download))
	mux.Handle("/", httpapi.Handle(func(http.ResponseWriter, *http.Request) error { return httpapi.ErrNotFound }))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

// Errors as agents see them.
var (
	errTokenInvalid = &httpapi.Error{Status: http.StatusUnauthorized, Code: "token_invalid",
		Message: "This deployment token is not valid: it may have expired, been revoked or been used up. Create a new token in the EasyRMM console."}
	errKeyInUse = &httpapi.Error{Status: http.StatusConflict, Code: "key_in_use",
		Message: "A device with this key is already enrolled."}
	errUnauthorized = &httpapi.Error{Status: http.StatusUnauthorized, Code: "agent_unauthorized",
		Message: "The request signature is not valid."}
	errClockSkew = &httpapi.Error{Status: http.StatusUnauthorized, Code: "clock_skew",
		Message: "The device clock is more than five minutes away from the server's. Correct the device's time."}
	errReplay = &httpapi.Error{Status: http.StatusUnauthorized, Code: "replayed",
		Message: "This request was already received."}
	errUnknownDevice = &httpapi.Error{Status: http.StatusUnauthorized, Code: "device_unknown",
		Message: "This device is not enrolled on this server."}
	errRateLimited = &httpapi.Error{Status: http.StatusTooManyRequests, Code: "rate_limited",
		Message: "Too many enrollments from this address. Try again shortly."}
	errMeshUnavailable = &httpapi.Error{Status: http.StatusServiceUnavailable, Code: "meshagent_unavailable",
		Message: "Remote access is not available for this device right now."}
)

func mapError(err error) error {
	for from, to := range map[error]*httpapi.Error{
		agents.ErrTokenInvalid:    errTokenInvalid,
		agents.ErrKeyInUse:        errKeyInUse,
		agents.ErrUnauthorized:    errUnauthorized,
		agents.ErrClockSkew:       errClockSkew,
		agents.ErrReplay:          errReplay,
		agents.ErrUnknownDevice:   errUnknownDevice,
		agents.ErrRateLimited:     errRateLimited,
		agents.ErrMeshUnavailable: errMeshUnavailable,
	} {
		if errors.Is(err, from) {
			return to
		}
	}
	return err
}

// readBody reads a request body of at most agentproto.MaxBody bytes.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, agentproto.MaxBody))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		return nil, &httpapi.Error{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Message: "The request body is too large."}
	}
	if err != nil {
		return nil, httpapi.BadRequest("The request body could not be read.")
	}
	return b, nil
}

// decode parses a JSON body strictly.
func decode(r *http.Request, body []byte, dst any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return &httpapi.Error{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Send the request body as application/json."}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return httpapi.BadRequest("The request body is not valid JSON for this endpoint.")
	}
	if dec.More() {
		return httpapi.BadRequest("The request body must be a single JSON object.")
	}
	return nil
}

func (a *API) enroll(w http.ResponseWriter, r *http.Request) error {
	body, err := readBody(w, r)
	if err != nil {
		return err
	}
	var in agentproto.EnrollRequest
	if err := decode(r, body, &in); err != nil {
		return err
	}
	out, err := a.svc.Enroll(r.Context(), httpapi.ClientIP(r), in)
	if err != nil {
		if errors.Is(err, agents.ErrRateLimited) {
			w.Header().Set("Retry-After", "5")
		}
		return mapError(err)
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

type signedHandler func(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error

// signed authenticates the request before calling h.
func (a *API) signed(h signedHandler) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		body, err := readBody(w, r)
		if err != nil {
			return err
		}
		target := r.RequestURI
		if target == "" {
			target = r.URL.RequestURI()
		}
		d, err := a.svc.Authenticate(r.Context(), r.Header.Get("Authorization"), r.Method, target, body)
		if err != nil {
			return mapError(err)
		}
		return h(w, r, d, body)
	}
}

func (a *API) heartbeat(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in agentproto.HeartbeatRequest
	if err := decode(r, body, &in); err != nil {
		return err
	}
	out, err := a.svc.Heartbeat(r.Context(), d, httpapi.ClientIP(r), in)
	if err != nil {
		return mapError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) meshAgent(w http.ResponseWriter, r *http.Request, _ *agents.Device, _ []byte) error {
	q := r.URL.Query()
	dl, err := a.svc.MeshAgentBinary(r.Context(), q.Get("os"), q.Get("arch"))
	if err != nil {
		return mapError(err)
	}
	defer func() { _ = dl.Body.Close() }()
	w.Header().Set("Content-Type", "application/octet-stream")
	if dl.Length >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(dl.Length, 10))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, dl.Body); err != nil {
		a.log.Warn("agentapi: sending MeshAgent failed", "error", err)
	}
	return nil
}

func (a *API) meshSettings(w http.ResponseWriter, r *http.Request, d *agents.Device, _ []byte) error {
	b, err := a.svc.MeshAgentSettings(r.Context(), d)
	if err != nil {
		return mapError(err)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(b) //nolint:gosec // MeshCentral's settings file, served as text/plain with nosniff
	return nil
}

func (a *API) installer(w http.ResponseWriter, _ *http.Request) error {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(a.install)
	return nil
}

func (a *API) download(w http.ResponseWriter, r *http.Request) error {
	name := r.PathValue("file")
	if name == "SHA256SUMS" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, a.builds.Checksums())
		return nil
	}
	f, b, err := a.builds.Open(name)
	if err != nil {
		return httpapi.ErrNotFound
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+b.File+`"`)
	w.Header().Set("X-Checksum-Sha256", b.SHA256)
	http.ServeContent(w, r, "", b.ModTime(), f)
	return nil
}
