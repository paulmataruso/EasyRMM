package agentapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// The two routes of moving an agent between addresses (ADR-0061, slice 1).

// moveWait bounds recording an agent's move report.
const moveWait = 30 * time.Second

var (
	errAddressNotServed = &httpapi.Error{Status: http.StatusMisdirectedRequest, Code: "address_not_served",
		Message: "This server does not answer agents on that address, or the request did not arrive there."}
	errNoConfirmation = &httpapi.Error{Status: http.StatusServiceUnavailable, Code: "address_unconfirmable",
		Message: "The server cannot confirm its address right now."}
)

// hostOf returns the host of an origin or a Host header in the one form two
// spellings of the same address share: lower case, without the default
// port.
func hostOf(hostport string) string {
	h := strings.ToLower(strings.TrimSpace(hostport))
	return strings.TrimSuffix(h, ":443")
}

// served returns the origin, among the ones agents are served on, that the
// address names, in the form the agent dialed it ("" when there is none).
func (a *API) served(address string) string {
	want, err := agentproto.MoveTarget(address)
	if err != nil {
		return ""
	}
	for origin := range a.scripts {
		if got, err := agentproto.MoveTarget(origin); err == nil && got == want {
			return want
		}
	}
	return ""
}

// address confirms the address a device asks about. It signs only for an
// enrolled device (the route's signature check), for an address the server
// serves agents on, and when the request itself arrived at that address, so
// that the confirmation says what the agent dialed and not what the
// request claims.
func (a *API) address(w http.ResponseWriter, r *http.Request, _ *agents.Device, body []byte) error {
	var in agentproto.AddressRequest
	if err := decode(r, body, &in); err != nil {
		return err
	}
	origin := a.served(in.Address)
	if origin == "" {
		return errAddressNotServed
	}
	u, err := url.Parse(origin)
	if err != nil || hostOf(u.Host) != hostOf(r.Host) {
		return errAddressNotServed
	}
	c, _ := r.Context().Value(signedCallKey{}).(signedCall)
	ans, err := a.svc.ConfirmAddress(r.Context(), c.req, origin)
	switch {
	case errors.Is(err, agents.ErrNoKey):
		return errNoConfirmation
	case err != nil:
		return mapError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, ans)
	return nil
}

// moved records an agent's report of changing address.
func (a *API) moved(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in agentproto.MoveReport
	if err := decode(r, body, &in); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), moveWait)
	defer cancel()
	if err := a.svc.Moved(ctx, d, httpapi.ClientIP(r), in); err != nil {
		if errors.Is(err, agents.ErrBadReport) {
			return httpapi.BadRequest("The move report is not valid.")
		}
		return mapError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
