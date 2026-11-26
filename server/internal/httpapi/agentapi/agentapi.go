// Package agentapi serves the EasyRMM agent (ADR-0015, ADR-0017):
// enrollment with a deployment token, signed heartbeats, MeshAgent
// delivery, jobs, and the agent downloads and installers: install.ps1 for
// Windows, install.sh for Linux.
//
// These routes are reached without a browser session and without CSRF
// checks; enrollment is authorized by the token, everything else by the
// device's Ed25519 signature.
package agentapi

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agentchannel"
	"github.com/paulmataruso/easyrmm/server/internal/agentlogs"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/hardware"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/inventory"
	"github.com/paulmataruso/easyrmm/server/internal/jobs"
)

//go:embed install.sh.tmpl
var installTemplate string

//go:embed install.ps1.tmpl
var installPSTemplate string

var (
	installScript   = template.Must(template.New("install.sh").Parse(installTemplate))
	installPSScript = template.Must(template.New("install.ps1").Parse(installPSTemplate))
)

// API serves the agent routes.
type API struct {
	svc     *agents.Service
	builds  *agents.Builds
	scripts map[string]installers // per console origin
	primary installers
	ca      []byte
	caDER   []byte
	jobs    *jobs.Service
	inv     *inventory.Service
	hw      *hardware.Service
	logs    *agentlogs.Service
	ep      EasyPatchInstalls
	repairs Repairs
	channel *agentchannel.Hub
	log     *slog.Logger

	// Per-device limits on signed requests.
	requests    *auth.KeyedLimiter
	inventories *auth.KeyedLimiter
	hardware    *auth.KeyedLimiter
	logLimit    *auth.KeyedLimiter
	upgrades    *auth.KeyedLimiter
	pollMu      sync.Mutex
	polls       map[uuid.UUID]int
}

// What one device may send. An agent sends a heartbeat a minute, keeps one
// job poll open, a start and a result for each job, an inventory when it
// changes (collected hourly) and a hardware report every 30 minutes; a device that sends far more is refused with
// 429 and backs off. Limits are spent only once a request's signature is
// verified, so requests naming someone else's device cannot use up its
// allowance.
const (
	requestEvery   = time.Second
	requestBurst   = 120
	inventoryEvery = 10 * time.Minute
	inventoryBurst = 6
	hardwareEvery  = 10 * time.Minute
	hardwareBurst  = 6
	// An agent sends logs every 30 seconds, every 2 while someone watches.
	logEvery = time.Second
	logBurst = 10
	maxPolls = 4
	// maxTracked bounds the devices the limits remember; idle ones are
	// forgotten first.
	maxTracked = 200_000
)

// bodyTimeout is how long a request body may take to arrive. The server
// has no read timeout of its own (it also carries WebSockets and long
// polls), so a body that stalls is given up on here. A variable for tests.
var bodyTimeout = 2 * time.Minute

// EasyPatchInstalls settles EasyPatch agent installs with each heartbeat
// (ADR-0031).
type EasyPatchInstalls interface {
	AgentHeartbeat(ctx context.Context, deviceID uuid.UUID, st *agentproto.EasyPatchInstallStatus) *agentproto.SignedEasyPatchInstall
}

// Repairs hands out and settles repair steps with each heartbeat
// (ADR-0069).
type Repairs interface {
	AgentHeartbeat(ctx context.Context, deviceID uuid.UUID, rep *agentproto.RepairReport) *agentproto.SignedRepair
}

// easyPatchWait bounds the EasyPatch side of a heartbeat, which may call
// EasyPatch to prepare an install.
const easyPatchWait = 45 * time.Second

// removedWait bounds recording an agent's removal report.
const removedWait = 30 * time.Second

// installers are an origin's install scripts.
type installers struct{ sh, ps1 []byte }

// Address is a console origin agents can enroll through (ADR-0016).
type Address struct {
	// URL is the origin, https://rmm.example.com or https://203.0.113.10.
	URL string
	// Pin is the curl public-key pin of the origin's certificate when it
	// comes from the server's own certificate authority.
	Pin string
	// KeyPin is the same key's pin for PowerShell (pki.Authority.KeyPin).
	KeyPin string
}

// New builds the API. addresses are the console origins, the public URL
// first; ca is the internal certificate authority's PEM certificate, or nil.
func New(svc *agents.Service, builds *agents.Builds, addresses []Address, ca []byte, log *slog.Logger) (*API, error) {
	if len(addresses) == 0 {
		return nil, errors.New("agentapi: no server address")
	}
	a := &API{svc: svc, builds: builds, scripts: map[string]installers{}, ca: ca, log: log,
		requests:    auth.NewKeyedLimiter(requestEvery, requestBurst, maxTracked),
		inventories: auth.NewKeyedLimiter(inventoryEvery, inventoryBurst, maxTracked),
		hardware:    auth.NewKeyedLimiter(hardwareEvery, hardwareBurst, maxTracked),
		logLimit:    auth.NewKeyedLimiter(logEvery, logBurst, maxTracked),
		upgrades:    auth.NewKeyedLimiter(agentproto.ChannelUpgradeEvery, agentproto.ChannelUpgradeBurst, maxTracked),
		polls:       map[uuid.UUID]int{},
	}
	if ca != nil {
		b, _ := pem.Decode(ca)
		if b == nil || b.Type != "CERTIFICATE" {
			return nil, errors.New("agentapi: the certificate authority is not a PEM certificate")
		}
		a.caDER = b.Bytes
	}
	for i, addr := range addresses {
		server := strings.TrimSuffix(addr.URL, "/")
		if !safeInScript(server + addr.Pin + addr.KeyPin) {
			return nil, errors.New("agentapi: the server address cannot be put in the installer")
		}
		if (addr.Pin != "" || addr.KeyPin != "") && ca == nil {
			return nil, errors.New("agentapi: a pinned address needs the certificate authority")
		}
		data := struct {
			Server      string
			HTTPS       bool
			Pin, KeyPin string
		}{server, strings.HasPrefix(server, "https://"), addr.Pin, addr.KeyPin}
		var sh, ps1 bytes.Buffer
		if err := installScript.Execute(&sh, data); err != nil {
			return nil, err
		}
		if err := installPSScript.Execute(&ps1, data); err != nil {
			return nil, err
		}
		// Windows PowerShell reads a script without a byte order mark in the
		// ANSI code page, and the console one-liner downloads it as text.
		ps1Bytes := bytes.ReplaceAll(ps1.Bytes(), []byte("\n"), []byte("\r\n"))
		a.scripts[server] = installers{sh: sh.Bytes(), ps1: ps1Bytes}
		if i == 0 {
			a.primary = a.scripts[server]
		}
	}
	return a, nil
}

// safeInScript reports whether s can go in single quotes in both
// installers: printable ASCII without quotes, backslashes, dollars or
// backticks.
func safeInScript(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e || strings.ContainsRune("'\\\"$`", r) {
			return false
		}
	}
	return true
}

// WithJobs serves job delivery from j.
func (a *API) WithJobs(j *jobs.Service) *API {
	a.jobs = j
	return a
}

// WithInventory stores inventory and metrics in inv (ADR-0018).
func (a *API) WithInventory(inv *inventory.Service) *API {
	a.inv = inv
	return a
}

// WithHardware stores hardware reports in hw (ADR-0065).
func (a *API) WithHardware(hw *hardware.Service) *API {
	a.hw = hw
	return a
}

// WithAgentLogs stores agents' log records in logs and has heartbeats carry
// how to log (ADR-0069).
func (a *API) WithAgentLogs(logs *agentlogs.Service) *API {
	a.logs = logs
	return a
}

// WithEasyPatch has heartbeats carry EasyPatch agent installs (ADR-0031).
func (a *API) WithEasyPatch(ep EasyPatchInstalls) *API {
	a.ep = ep
	return a
}

// WithRepairs has heartbeats carry repair steps (ADR-0069).
func (a *API) WithRepairs(r Repairs) *API {
	a.repairs = r
	return a
}

// WithChannel serves the agent's WebSocket channel from h (ADR-0059). With
// the channel off the route is not served and nothing else changes.
func (a *API) WithChannel(h *agentchannel.Hub) *API {
	a.channel = h
	return a
}

// Handler returns the handler for everything under agentproto.PathPrefix.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+agentproto.PathEnroll, httpapi.Handle(a.enroll))
	mux.Handle("POST "+agentproto.PathHeartbeat, httpapi.Handle(a.signedFor(agentproto.MaxBody, nil, true, a.heartbeat)))
	mux.Handle("POST "+agentproto.PathRemoved, httpapi.Handle(a.signedFor(agentproto.MaxBody, nil, true, a.removed)))
	mux.Handle("GET "+agentproto.PathMeshAgent, httpapi.Handle(a.signed(a.meshAgent)))
	mux.Handle("GET "+agentproto.PathMeshSettings, httpapi.Handle(a.signed(a.meshSettings)))
	if a.jobs != nil {
		mux.Handle("POST "+agentproto.PathJobsPoll, httpapi.Handle(a.signed(a.poll)))
		mux.Handle("POST /api/agent/v1/jobs/{run}/start", httpapi.Handle(a.signed(a.start)))
		mux.Handle("POST /api/agent/v1/jobs/{run}/result", httpapi.Handle(a.signedLimit(agentproto.MaxResultBody, a.result)))
	}
	if a.inv != nil {
		mux.Handle("POST "+agentproto.PathInventory, httpapi.Handle(a.signedWith(agentproto.MaxInventoryBody, a.inventories, a.inventory)))
	}
	if a.hw != nil {
		mux.Handle("POST "+agentproto.PathHardware, httpapi.Handle(a.signedWith(agentproto.MaxHardwareBody, a.hardware, a.hardwareReport)))
	}
	if a.logs != nil {
		mux.Handle("POST "+agentproto.PathAgentLogs, httpapi.Handle(a.signedWith(agentproto.MaxLogBody, a.logLimit, a.agentLogs)))
	}
	if a.channel.Enabled() {
		mux.Handle("GET "+agentproto.PathChannel, httpapi.Handle(a.signedWith(1024, a.upgrades, a.channelUpgrade)))
	}
	mux.Handle("GET /api/agent/v1/install.sh", httpapi.Handle(a.installer))
	mux.Handle("GET /api/agent/v1/install.ps1", httpapi.Handle(a.installer))
	mux.Handle("GET "+agentproto.PathCA, httpapi.Handle(a.authority))
	mux.Handle("GET "+agentproto.PathCACert, httpapi.Handle(a.authorityCert))
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
		Message: "Too many enrollments from this address. Try again shortly.", RetryAfter: 5 * time.Second}
	errRejected = &httpapi.Error{Status: http.StatusForbidden, Code: agentproto.CodeEnrollmentRejected,
		Message: "This device was rejected in the EasyRMM console. Uninstall the agent, or reinstall it to ask again."}
	errTooManyWaiting = &httpapi.Error{Status: http.StatusTooManyRequests, Code: "too_many_waiting",
		Message: "Too many devices are waiting for approval. Approve or reject some in the EasyRMM console, then try again.", RetryAfter: 5 * time.Minute}
	errMeshUnavailable = &httpapi.Error{Status: http.StatusServiceUnavailable, Code: "meshagent_unavailable",
		Message: "Remote access is not available for this device right now."}
	errRunNotFound = &httpapi.Error{Status: http.StatusNotFound, Code: "run_not_found",
		Message: "This device has no such job run."}
	errBadResult = &httpapi.Error{Status: http.StatusBadRequest, Code: "result_invalid",
		Message: "The job result is not valid."}
	errBadReport = &httpapi.Error{Status: http.StatusBadRequest, Code: "report_invalid",
		Message: "The removal report is not valid."}
	errBadInventory = &httpapi.Error{Status: http.StatusBadRequest, Code: "inventory_invalid",
		Message: "The inventory is not valid JSON."}
	errBadHardware = &httpapi.Error{Status: http.StatusBadRequest, Code: "hardware_invalid",
		Message: "The hardware report is not valid JSON."}
	errBadLogs = &httpapi.Error{Status: http.StatusBadRequest, Code: "logs_invalid",
		Message: "The log batch is not valid."}
	errTooFrequent = &httpapi.Error{Status: http.StatusTooManyRequests, Code: "rate_limited",
		Message: "This device is sending requests more often than an agent does. Try again shortly."}
	errTooManyPolls = &httpapi.Error{Status: http.StatusTooManyRequests, Code: "rate_limited",
		Message: "This device already has as many job polls open as it may."}
	errBodyTimeout = &httpapi.Error{Status: http.StatusRequestTimeout, Code: "body_timeout",
		Message: "The request body took too long to arrive."}
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
		agents.ErrRejected:        errRejected,
		agents.ErrTooManyWaiting:  errTooManyWaiting,
		agents.ErrMeshUnavailable: errMeshUnavailable,
		jobs.ErrRunNotFound:       errRunNotFound,
		jobs.ErrBadResult:         errBadResult,
		agents.ErrBadReport:       errBadReport,
		inventory.ErrBadInventory: errBadInventory,
		hardware.ErrBadReport:     errBadHardware,
		agentlogs.ErrBadBatch:     errBadLogs,
	} {
		if errors.Is(err, from) {
			return to
		}
	}
	return err
}

// readBody reads a request body of at most limit bytes, arriving within
// bodyTimeout.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(bodyTimeout))
	src := &eofReader{ReadCloser: r.Body}
	b, err := io.ReadAll(http.MaxBytesReader(w, src, limit))
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		return nil, refuseUnread(w, r, src.ended, &httpapi.Error{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Message: "The request body is too large."})
	case errors.Is(err, os.ErrDeadlineExceeded):
		return nil, refuseUnread(w, r, src.ended, errBodyTimeout)
	case err != nil:
		return nil, refuseUnread(w, r, src.ended, httpapi.BadRequest("The request body could not be read."))
	}
	// net/http clears the deadline when the body ends; it is cleared here
	// too, so that nothing after the body, such as a long poll's wait, can
	// be cut off by it.
	_ = rc.SetReadDeadline(time.Time{})
	return b, nil
}

// refuseUnread prepares to answer err to a request whose body may not have
// been read to its end. Over HTTP/1, net/http reads up to 256 KiB of what
// is left before answering, to keep the connection, with no time limit: a
// client that stalls would hold the request open for good. An expired read
// deadline makes that read fail at once, and net/http then answers and
// closes the connection.
//
// Not when the body has ended (or there is none): net/http is then already
// reading the connection in the background, to notice the client going
// away, and an expired deadline there would cancel the context of every
// later request on a connection it keeps. HTTP/2 ends the stream on its
// own and needs nothing here.
func refuseUnread(w http.ResponseWriter, r *http.Request, ended bool, err error) error {
	if r.ProtoMajor == 1 && !ended && r.Body != nil && r.Body != http.NoBody {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	}
	return err
}

// eofReader notes whether a body was read to its end.
type eofReader struct {
	io.ReadCloser
	ended bool
}

func (e *eofReader) Read(p []byte) (int, error) {
	n, err := e.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) {
		e.ended = true
	}
	return n, err
}

// decode parses a JSON body. Fields this server does not know are ignored
// (ADR-0009, "Evolving the protocol"): an agent newer than its server, as
// after a rollback (ADR-0052), may send fields a later release added, and
// refusing them would cut it off. Each body is decoded into a fixed type and,
// but for enrollment, signed by an enrolled device; malformed JSON and values
// of the wrong type are still refused.
func decode(r *http.Request, body []byte, dst any) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return &httpapi.Error{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Send the request body as application/json."}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
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
		return mapError(err)
	}
	// A device waiting for approval is accepted, not yet created.
	status := http.StatusCreated
	if out.Pending != nil {
		status = http.StatusAccepted
	}
	httpapi.WriteJSON(w, status, out)
	return nil
}

type signedHandler func(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error

// signed authenticates the request before calling h.
func (a *API) signed(h signedHandler) httpapi.HandlerFunc {
	return a.signedLimit(agentproto.MaxBody, h)
}

// signedLimit is signed with a body limit of its own.
func (a *API) signedLimit(limit int64, h signedHandler) httpapi.HandlerFunc {
	return a.signedWith(limit, nil, h)
}

// signedWith is signedLimit with a per-device limit of its own besides the
// one every signed request counts against.
//
// The header is checked before the body is read: a request that names no
// enrolled device, or a device that has used up its allowance, is refused
// without reading what it sends.
func (a *API) signedWith(limit int64, extra *auth.KeyedLimiter, h signedHandler) httpapi.HandlerFunc {
	return a.signedFor(limit, extra, false, h)
}

// signedFor is signedWith that, with retired, also serves the agents of
// devices removed by force (ADR-0050). Other routes answer them as unknown
// devices.
func (a *API) signedFor(limit int64, extra *auth.KeyedLimiter, retired bool, h signedHandler) httpapi.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		p, err := a.svc.BeginSigned(r.Context(), r.Header.Get("Authorization"))
		if err != nil {
			return refuseUnread(w, r, false, mapError(err))
		}
		key := p.DeviceID().String()
		if !a.requests.Ready(key) || (extra != nil && !extra.Ready(key)) {
			return refuseUnread(w, r, false, errTooFrequent)
		}
		body, err := readBody(w, r, limit)
		if err != nil {
			return err
		}
		target := r.RequestURI
		if target == "" {
			target = r.URL.RequestURI()
		}
		d, err := a.svc.FinishSigned(r.Context(), p, r.Method, target, body)
		if err != nil {
			return mapError(err)
		}
		if !a.requests.Allow(key) || (extra != nil && !extra.Allow(key)) {
			return errTooFrequent
		}
		if d.Retired && !retired {
			return errUnknownDevice
		}
		r = r.WithContext(context.WithValue(r.Context(), signedCallKey{}, signedCall{req: p, target: target}))
		return h(w, r, d, body)
	}
}

// signedCall is a verified request, for answers signed back to it.
type signedCall struct {
	req    *agents.SignedRequest
	target string
}

type signedCallKey struct{}

// signDownload signs an answer the agent will run (MeshAgent and its
// settings) back to the signed request it answers.
func (a *API) signDownload(w http.ResponseWriter, r *http.Request, body []byte) {
	c, _ := r.Context().Value(signedCallKey{}).(signedCall)
	w.Header().Set(agentproto.HeaderDownloadSignature, a.svc.SignDownload(c.req, c.target, body))
}

// enterPoll counts an open job poll for a device, unless it has maxPolls
// open already: each holds a connection and a goroutine while it waits.
func (a *API) enterPoll(device uuid.UUID) bool {
	a.pollMu.Lock()
	defer a.pollMu.Unlock()
	if a.polls[device] >= maxPolls {
		return false
	}
	a.polls[device]++
	return true
}

func (a *API) leavePoll(device uuid.UUID) {
	a.pollMu.Lock()
	defer a.pollMu.Unlock()
	if a.polls[device]--; a.polls[device] <= 0 {
		delete(a.polls, device)
	}
}

func (a *API) heartbeat(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in agentproto.HeartbeatRequest
	if err := decode(r, body, &in); err != nil {
		return err
	}
	if d.Retired {
		out, err := a.svc.RetiredHeartbeat(r.Context(), d)
		if err != nil {
			return mapError(err)
		}
		httpapi.WriteJSON(w, http.StatusOK, out)
		return nil
	}
	out, err := a.svc.Heartbeat(r.Context(), d, httpapi.ClientIP(r), in)
	if err != nil {
		return mapError(err)
	}
	if a.channel.Enabled() {
		// The heartbeat confirms the connection it names (ADR-0059).
		c, _ := r.Context().Value(signedCallKey{}).(signedCall)
		a.channel.Heartbeat(d.ID, in.Transport, c.req.SignedAt())
		if in.Transport != nil && in.Transport.LastReplayed != 0 {
			a.log.Warn("agent: an upgrade of this device's channel was replayed by someone else", "device_id", d.ID)
		}
		if devscope.Allowed(d.OrganizationID) {
			out.Features = append(out.Features, agentproto.FeatureChannel)
			out.Instance = a.channel.Instance()
			out.JobsWaiting = a.channel.TakeJobsWaiting(d.ID)
			if !out.JobsWaiting && a.jobs != nil && a.channel.Live(d.ID) {
				// A live agent holds no poll: work the channel has not
				// carried (a lost push, a held-back run) is found here.
				if w, err := a.jobs.Waiting(r.Context(), d.ID); err == nil {
					out.JobsWaiting = w
				}
			}
		}
	}
	if a.inv != nil {
		// Metrics and the inventory hash are extras: a failure here is
		// logged, and the heartbeat still counts.
		if in.Metrics != nil {
			if err := a.inv.RecordMetrics(r.Context(), d.ID, *in.Metrics); err != nil {
				a.log.Warn("agent: storing metrics failed", "error", err, "device_id", d.ID)
			}
		}
		if out.InventoryHash, err = a.inv.Hash(r.Context(), d.ID); err != nil {
			a.log.Warn("agent: reading the inventory hash failed", "error", err, "device_id", d.ID)
			out.InventoryHash = "unknown" // never equal to an agent's hash, so it uploads
		}
	}
	if a.logs != nil && out.Uninstall == nil {
		if out.Logs, err = a.logs.Instructions(r.Context(), d.ID); err != nil {
			a.log.Warn("agent: reading the log instructions failed", "error", err, "device_id", d.ID)
		}
	}
	if a.ep != nil && out.Uninstall == nil {
		// Settled to the end even if the agent hangs up, so an attempt is
		// never left half recorded.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), easyPatchWait)
		out.EasyPatchInstall = a.ep.AgentHeartbeat(ctx, d.ID, in.EasyPatch)
		cancel()
	}
	if a.repairs != nil && out.Uninstall == nil {
		out.Repair = a.repairs.AgentHeartbeat(r.Context(), d.ID, in.Repair)
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

// channelUpgrade opens the agent's WebSocket channel (ADR-0059). The
// request is verified; the connection stays pending until a heartbeat names
// it.
func (a *API) channelUpgrade(w http.ResponseWriter, r *http.Request, d *agents.Device, _ []byte) error {
	c, _ := r.Context().Value(signedCallKey{}).(signedCall)
	return a.channel.Upgrade(w, r, agentchannel.Peer{
		Device: d.ID, Org: d.OrganizationID, Key: c.req.PublicKey(), Nonce: c.req.Nonce(), SignedAt: c.req.SignedAt(),
	})
}

// removed takes an agent's report on uninstalling itself (ADR-0050).
func (a *API) removed(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in agentproto.RemovedReport
	if err := decode(r, body, &in); err != nil {
		return err
	}
	// Recorded to the end even if the agent hangs up: it may be deleting
	// itself.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), removedWait)
	defer cancel()
	if err := a.svc.Removed(ctx, d, httpapi.ClientIP(r), in); err != nil {
		return mapError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) inventory(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return &httpapi.Error{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Send the request body as application/json."}
	}
	hash, err := a.inv.Record(r.Context(), d.ID, body)
	if err != nil {
		return mapError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, agentproto.InventoryResponse{Hash: hash})
	return nil
}

// hardwareReport stores a device's hardware report (ADR-0065).
func (a *API) hardwareReport(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		return &httpapi.Error{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Send the request body as application/json."}
	}
	if err := a.hw.Record(r.Context(), d.ID, body); err != nil {
		return mapError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// agentLogs stores a batch of a device's log records and answers with what
// the server took care of and how to log (ADR-0069).
func (a *API) agentLogs(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in agentproto.LogBatch
	if err := decode(r, body, &in); err != nil {
		return err
	}
	ack, err := a.logs.Ingest(r.Context(), d.ID, in)
	if err != nil {
		return mapError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, ack)
	return nil
}

func (a *API) poll(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in agentproto.PollRequest
	if err := decode(r, body, &in); err != nil {
		return err
	}
	if !a.enterPoll(d.ID) {
		return errTooManyPolls
	}
	defer a.leavePoll(d.ID)
	out, err := a.jobs.Poll(r.Context(), d.ID, in.Accepts)
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
	b, err := a.svc.MeshAgentBinary(r.Context(), q.Get("os"), q.Get("arch"))
	if err != nil {
		return mapError(err)
	}
	a.signDownload(w, r, b)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	if _, err := w.Write(b); err != nil { //nolint:gosec // MeshCentral's MeshAgent binary, served as application/octet-stream with nosniff
		a.log.Warn("agentapi: sending MeshAgent failed", "error", err)
	}
	return nil
}

func (a *API) meshSettings(w http.ResponseWriter, r *http.Request, d *agents.Device, _ []byte) error {
	b, err := a.svc.MeshAgentSettings(r.Context(), d)
	if err != nil {
		return mapError(err)
	}
	a.signDownload(w, r, b)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(b) //nolint:gosec // MeshCentral's settings file, served as text/plain with nosniff
	return nil
}

// installer serves the install script for the address the request came
// to, so a machine installed by IP address keeps using the IP address.
// installer serves the install script for the address the request came
// to: install.sh, or install.ps1 for Windows.
func (a *API) installer(w http.ResponseWriter, r *http.Request) error {
	scripts := a.primary
	if o, ok := httpapi.OriginOf(r); ok {
		if s, ok := a.scripts[o.Console]; ok {
			scripts = s
		}
	}
	if strings.HasSuffix(r.URL.Path, ".ps1") {
		w.Header().Set("Content-Type", "text/plain; charset=us-ascii")
		_, _ = w.Write(scripts.ps1)
		return nil
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(scripts.sh)
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

// authorityCert serves the same certificate in DER, as the .crt file Windows
// installs from its context menu (Install Certificate) and macOS from Finder.
func (a *API) authorityCert(w http.ResponseWriter, _ *http.Request) error {
	if a.caDER == nil {
		return httpapi.ErrNotFound
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="easyrmm-ca.crt"`)
	_, _ = w.Write(a.caDER)
	return nil
}

// HeaderDeployToken is the header an installer sends its deployment token
// in when it downloads the agent: the server hands a build to the
// organization the token belongs to (package devscope).
const HeaderDeployToken = "X-Easyrmm-Token" //nolint:gosec // a header name, not a credential

// servedBuilds are the builds this download is for. Without a dev scope
// they are the server's, as ever. With one, a request that names a device by
// its signature, or an organization by a deployment token, within the scope
// gets the server's builds; every other gets the stable ones.
func (a *API) servedBuilds(r *http.Request) (*agents.Builds, error) {
	if !devscope.Active() {
		return a.builds, nil
	}
	org := uuid.Nil
	switch h := r.Header.Get("Authorization"); {
	case h != "":
		p, err := a.svc.BeginSigned(r.Context(), h)
		if err != nil {
			return nil, mapError(err)
		}
		if !a.requests.Allow(p.DeviceID().String()) {
			return nil, errTooFrequent
		}
		target := r.RequestURI
		if target == "" {
			target = r.URL.RequestURI()
		}
		d, err := a.svc.FinishSigned(r.Context(), p, r.Method, target, nil)
		if err != nil {
			return nil, mapError(err)
		}
		org = d.OrganizationID
	case r.Header.Get(HeaderDeployToken) != "":
		if o, ok := a.svc.TokenOrg(r.Context(), r.Header.Get(HeaderDeployToken)); ok {
			org = o
		}
	}
	if devscope.Allowed(org) {
		return a.builds, nil
	}
	return a.svc.BuildsFor(org), nil
}

func (a *API) download(w http.ResponseWriter, r *http.Request) error {
	builds, err := a.servedBuilds(r)
	if err != nil {
		return err
	}
	if builds == nil {
		return httpapi.ErrNotFound
	}
	name := r.PathValue("file")
	if name == "SHA256SUMS" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, builds.Checksums()) //nolint:gosec // the sums of the server's own builds, served as text/plain
		return nil
	}
	f, b, err := builds.Open(name)
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
