// Package agentapi serves the EasyRMM agent (ADR-0015, ADR-0017):
// enrollment with a deployment token, signed heartbeats, MeshAgent
// delivery, jobs, and the agent downloads and Linux installer.
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

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
)

//go:embed install.sh.tmpl
var installTemplate string

var installScript = template.Must(template.New("install.sh").Parse(installTemplate))

// API serves the agent routes.
type API struct {
	svc     *agents.Service
	builds  *agents.Builds
	scripts map[string][]byte // install script per console origin
	primary []byte
	ca      []byte
	jobs    *jobs.Service
	log     *slog.Logger
}

// Address is a console origin agents can enroll through (ADR-0016).
type Address struct {
	// URL is the origin, https://rmm.example.com or https://203.0.113.10.
	URL string
	// Pin is the curl public-key pin of the origin's certificate when it
	// comes from the server's own certificate authority.
	Pin string
}

// New builds the API. addresses are the console origins, the public URL
// first; ca is the internal certificate authority's PEM certificate, or nil.
func New(svc *agents.Service, builds *agents.Builds, addresses []Address, ca []byte, log *slog.Logger) (*API, error) {
	if len(addresses) == 0 {
		return nil, errors.New("agentapi: no server address")
	}
	a := &API{svc: svc, builds: builds, scripts: map[string][]byte{}, ca: ca, log: log}
	for i, addr := range addresses {
		server := strings.TrimSuffix(addr.URL, "/")
		if strings.ContainsAny(server+addr.Pin, "'\\\n\r\"$`") {
			return nil, errors.New("agentapi: the server address cannot be put in the installer")
		}
		if addr.Pin != "" && ca == nil {
			return nil, errors.New("agentapi: a pinned address needs the certificate authority")
		}
		var buf bytes.Buffer
		if err := installScript.Execute(&buf, struct {
			Server string
			HTTPS  bool
			Pin    string
		}{server, strings.HasPrefix(server, "https://"), addr.Pin}); err != nil {
			return nil, err
		}
		a.scripts[server] = buf.Bytes()
		if i == 0 {
			a.primary = buf.Bytes()
		}
	}
	return a, nil
}

// WithJobs serves job delivery from j.
func (a *API) WithJobs(j *jobs.Service) *API {
	a.jobs = j
	return a
}

// Handler returns the handler for everything under agentproto.PathPrefix.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+agentproto.PathEnroll, httpapi.Handle(a.enroll))
	mux.Handle("POST "+agentproto.PathHeartbeat, httpapi.Handle(a.signed(a.heartbeat)))
	mux.Handle("GET "+agentproto.PathMeshAgent, httpapi.Handle(a.signed(a.meshAgent)))
	mux.Handle("GET "+agentproto.PathMeshSettings, httpapi.Handle(a.signed(a.meshSettings)))
	if a.jobs != nil {
		mux.Handle("POST "+agentproto.PathJobsPoll, httpapi.Handle(a.signed(a.poll)))
		mux.Handle("POST /api/agent/v1/jobs/{run}/start", httpapi.Handle(a.signed(a.start)))
		mux.Handle("POST /api/agent/v1/jobs/{run}/result", httpapi.Handle(a.signedLimit(agentproto.MaxResultBody, a.result)))
	}
	mux.Handle("GET /api/agent/v1/install.sh", httpapi.Handle(a.installer))
	mux.Handle("GET "+agentproto.PathCA, httpapi.Handle(a.authority))
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
	errRunNotFound = &httpapi.Error{Status: http.StatusNotFound, Code: "run_not_found",
		Message: "This device has no such job run."}
	errBadResult = &httpapi.Error{Status: http.StatusBadRequest, Code: "result_invalid",
		Message: "The job result is not valid."}
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
		jobs.ErrRunNotFound:       errRunNotFound,
		jobs.ErrBadResult:         errBadResult,
	} {
		if errors.Is(err, from) {
			return to
		}
	}
	return err
}

// readBody reads a request body of at most limit bytes.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
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
	body, err := readBody(w, r, agentproto.MaxBody)
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
	return a.signedLimit(agentproto.MaxBody, h)
}

// signedLimit is signed with a body limit of its own.
func (a *API) signedLimit(limit int64, h signedHandler) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		body, err := readBody(w, r, limit)
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

func (a *API) poll(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in agentproto.PollRequest
	if err := decode(r, body, &in); err != nil {
		return err
	}
	out, err := a.jobs.Poll(r.Context(), d.ID)
	if err != nil && r.Context().Err() != nil {
		return nil //nolint:nilerr // the agent went away; there is no one to answer
	}
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) start(w http.ResponseWriter, r *http.Request, d *agents.Device, _ []byte) error {
	run, err := uuid.Parse(r.PathValue("run"))
	if err != nil {
		return errRunNotFound
	}
	out, err := a.jobs.Start(r.Context(), d.ID, run)
	if err != nil {
		return mapError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) result(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	run, err := uuid.Parse(r.PathValue("run"))
	if err != nil {
		return errRunNotFound
	}
	var in agentproto.ResultRequest
	if err := decode(r, body, &in); err != nil {
		return err
	}
	if err := a.jobs.Result(r.Context(), d.ID, run, in); err != nil {
		return mapError(err)
	}
	w.WriteHeader(http.StatusNoContent)
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

// installer serves the install script for the address the request came
// to, so a machine installed by IP address keeps using the IP address.
func (a *API) installer(w http.ResponseWriter, r *http.Request) error {
	script := a.primary
	if o, ok := httpapi.OriginOf(r); ok {
		if s, ok := a.scripts[o.Console]; ok {
			script = s
		}
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(script)
	return nil
}

// authority serves the internal certificate authority's certificate, which
// agents installed through a pinned address trust.
func (a *API) authority(w http.ResponseWriter, _ *http.Request) error {
	if a.ca == nil {
		return httpapi.ErrNotFound
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="easyrmm-ca.pem"`)
	_, _ = w.Write(a.ca)
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
