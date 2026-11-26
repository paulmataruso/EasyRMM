package agentapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"

	"github.com/paulmataruso/easyrmm/internal/qaticket"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/quickassist"
)

// QuickAssist is what the runner's requests need (ADR-0080).
type QuickAssist interface {
	Enroll(ctx context.Context, ip netip.Addr, req quickassist.EnrollRequest) (*quickassist.EnrollResult, error)
	Status(ctx context.Context, device uuid.UUID) (*quickassist.RunnerState, error)
	SetMeshNode(ctx context.Context, device uuid.UUID, nodeID string) error
	InstallConsent(ctx context.Context, device uuid.UUID, ip netip.Addr, accept bool) (*quickassist.Conversion, error)
	Converted(ctx context.Context, device uuid.UUID, ip netip.Addr) error
	RunnerEnd(ctx context.Context, device uuid.UUID, ip netip.Addr, reason string, rep *quickassist.Cleanup) error
}

// WithQuickAssist serves the Quick Assist runner's routes from q.
func (a *API) WithQuickAssist(q QuickAssist) *API {
	a.qa = q
	return a
}

func (a *API) registerQuickAssist(mux *http.ServeMux) {
	if a.qa == nil {
		return
	}
	mux.Handle("POST "+qaticket.PathEnroll, httpapi.Handle(a.qaEnroll))
	mux.Handle("POST "+qaticket.PathStatus, httpapi.Handle(a.signed(a.qaStatus)))
	mux.Handle("POST "+qaticket.PathEnd, httpapi.Handle(a.signed(a.qaEnd)))
	mux.Handle("POST "+qaticket.PathMesh, httpapi.Handle(a.signed(a.qaMesh)))
	mux.Handle("POST "+qaticket.PathInstall, httpapi.Handle(a.signed(a.qaInstall)))
	mux.Handle("POST "+qaticket.PathConverted, httpapi.Handle(a.signed(a.qaConverted)))
}

var (
	errQATicket = &httpapi.Error{Status: http.StatusUnauthorized, Code: "ticket_invalid", Message: "The ticket is not accepted. Ask for a new link."}
)

func mapQA(err error) error {
	switch {
	case errors.Is(err, quickassist.ErrTicket):
		return errQATicket
	case errors.Is(err, quickassist.ErrRateLimited):
		return errRateLimited
	}
	return err
}

func (a *API) qaEnroll(w http.ResponseWriter, r *http.Request) error {
	body, err := readBody(w, r, agentproto.MaxBody)
	if err != nil {
		return err
	}
	var in quickassist.EnrollRequest
	if err := decode(r, body, &in); err != nil {
		return err
	}
	out, err := a.qa.Enroll(r.Context(), httpapi.ClientIP(r), in)
	if err != nil {
		return mapQA(err)
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) qaStatus(w http.ResponseWriter, r *http.Request, d *agents.Device, _ []byte) error {
	st, err := a.qa.Status(r.Context(), d.ID)
	if err != nil {
		return mapQA(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, st)
	return nil
}

func (a *API) qaEnd(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in struct {
		Reason  string               `json:"reason"`
		Cleanup *quickassist.Cleanup `json:"cleanup"`
	}
	if err := decode(r, body, &in); err != nil {
		return err
	}
	if err := a.qa.RunnerEnd(r.Context(), d.ID, httpapi.ClientIP(r), in.Reason, in.Cleanup); err != nil {
		return mapQA(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) qaInstall(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in struct {
		Accept bool `json:"accept"`
	}
	if err := decode(r, body, &in); err != nil {
		return err
	}
	out, err := a.qa.InstallConsent(r.Context(), d.ID, httpapi.ClientIP(r), in.Accept)
	if err != nil {
		return mapQA(err)
	}
	if out == nil {
		out = &quickassist.Conversion{}
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) qaConverted(w http.ResponseWriter, r *http.Request, d *agents.Device, _ []byte) error {
	if err := a.qa.Converted(r.Context(), d.ID, httpapi.ClientIP(r)); err != nil {
		return mapQA(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) qaMesh(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in struct {
		NodeID string `json:"nodeId"`
	}
	if err := decode(r, body, &in); err != nil {
		return err
	}
	if err := a.qa.SetMeshNode(r.Context(), d.ID, in.NodeID); err != nil {
		return mapQA(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
