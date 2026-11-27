// Package jobkeyapi exposes rotating the server's job key (ADR-0057, slice 2):
// the ring, and starting, finishing and forgetting a rotation, replacing a lost
// key and recovering one. Every route needs settings.manage everywhere (super
// administrators); every change also needs step-up authentication (ADR-0055).
// No response carries a seed.
package jobkeyapi

import (
	"net/http"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves the routes.
type API struct {
	ring     *jobkeys.Ring
	sessions *httpapi.Sessions
}

// New builds the API; sessions asks for the step-up.
func New(ring *jobkeys.Ring, sessions *httpapi.Sessions) *API {
	return &API{ring: ring, sessions: sessions}
}

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, stepUp bool, h httpapi.HandlerFunc) {
		handler := httpapi.Handle(h)
		if stepUp {
			handler = a.sessions.RequireStepUp(handler)
		}
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(func(w http.ResponseWriter, r *http.Request) error {
			if !httpapi.Can(r, rbac.PermSettingsManage, rbac.Resource{}) {
				return apperr.Forbidden()
			}
			handler.ServeHTTP(w, r)
			return nil
		})))
	}
	r("GET /api/v1/settings/job-key", false, a.status)
	r("POST /api/v1/settings/job-key/rotate", true, a.rotate)
	r("POST /api/v1/settings/job-key/finish", true, a.finish)
	r("POST /api/v1/settings/job-key/forget", true, a.forget)
	r("POST /api/v1/settings/job-key/replace-lost", true, a.replaceLost)
	r("POST /api/v1/settings/job-key/recover", true, a.recoverKey)
}

// by is who asks: the signed-in person, through the console.
func by(r *http.Request) jobkeys.By {
	b := jobkeys.By{Actor: httpapi.Actor(r), Via: jobkeys.ViaConsole}
	if id := httpapi.IdentityFrom(r.Context()); id != nil {
		b.User = id.User.ID
	}
	return b
}

type keyView struct {
	Generation    int64      `json:"generation"`
	Fingerprint   string     `json:"fingerprint"`
	Reason        string     `json:"reason"`
	CreatedAt     time.Time  `json:"createdAt"`
	CutOverAt     *time.Time `json:"cutOverAt,omitempty"`
	CompromisedAt *time.Time `json:"compromisedAt,omitempty"`
	LostAt        *time.Time `json:"lostAt,omitempty"`
	SeedDeletedAt *time.Time `json:"seedDeletedAt,omitempty"`
	Held          bool       `json:"held"`
}

func view(k jobkeys.Key) keyView {
	return keyView{Generation: k.Generation, Fingerprint: k.Fingerprint(), Reason: string(k.Reason), CreatedAt: k.CreatedAt,
		CutOverAt: k.CutOverAt, CompromisedAt: k.CompromisedAt, LostAt: k.LostAt, SeedDeletedAt: k.SeedDeletedAt, Held: k.Held()}
}

func (a *API) status(w http.ResponseWriter, r *http.Request) error {
	var keys []keyView
	for _, k := range a.ring.Keys() {
		keys = append(keys, view(k))
	}
	instances, err := a.ring.Instances(r.Context())
	if err != nil {
		return err
	}
	type inst struct {
		ID       string    `json:"id"`
		Version  string    `json:"version"`
		Started  time.Time `json:"startedAt"`
		Reloaded time.Time `json:"reloadedAt"`
		Held     bool      `json:"held"`
	}
	servers := make([]inst, 0, len(instances))
	for _, i := range instances {
		servers = append(servers, inst{i.ID, i.Version, i.StartedAt, i.Reloaded, i.Held})
	}
	out := map[string]any{"floor": a.ring.Floor().Generation, "keys": keys, "servers": servers}
	if k, ok := a.ring.Progress(); ok {
		out["rotation"] = map[string]any{"generation": k.Generation, "reason": string(k.Reason), "startedAt": k.CreatedAt,
			"mayFinishAt": k.CreatedAt.Add(jobkeys.MinOverlap)}
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) rotate(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	s, err := a.ring.Start(r.Context(), jobkeys.Reason(in.Reason), by(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, map[string]any{"key": view(s.Key), "markedCompromised": s.Compromised, "endedPlannedRotation": s.Ended})
	return nil
}

func (a *API) finish(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		BackupTakenSinceStart bool `json:"backupTakenSinceStart"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	// The console never skips the 24 hours: only the host does.
	f, err := a.ring.Finish(r.Context(), jobkeys.FinishInput{BackupTaken: in.BackupTakenSinceStart, By: by(r)})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"key": view(f.Key), "devicesMoved": f.Moved, "devicesNotMoved": f.NotMoved})
	return nil
}

func generation(w http.ResponseWriter, r *http.Request) (int64, error) {
	var in struct {
		Generation int64 `json:"generation"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return 0, err
	}
	if in.Generation < 1 {
		return 0, apperr.Invalid("generation", "Give the key's generation.")
	}
	return in.Generation, nil
}

func (a *API) forget(w http.ResponseWriter, r *http.Request) error {
	g, err := generation(w, r)
	if err != nil {
		return err
	}
	n, err := a.ring.Forget(r.Context(), g, by(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"devicesNeedingRepinning": n})
	return nil
}

func (a *API) replaceLost(w http.ResponseWriter, r *http.Request) error {
	lost, k, err := a.ring.ReplaceLost(r.Context(), by(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, map[string]any{"lost": lost, "key": view(k)})
	return nil
}

func (a *API) recoverKey(w http.ResponseWriter, r *http.Request) error {
	g, err := generation(w, r)
	if err != nil {
		return err
	}
	n, err := a.ring.Recover(r.Context(), g, by(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"devicesNoLongerNeedingRepinning": n})
	return nil
}
