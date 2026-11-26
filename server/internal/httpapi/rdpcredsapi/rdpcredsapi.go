// Package rdpcredsapi exposes saved RDP credentials (ADR-0079). No route
// returns a password: the list shows a label, a domain and a user name.
package rdpcredsapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rdpcreds"
)

// StepUp is what the API asks of the session: nil when it was stepped up
// within the window (httpapi.Sessions).
type StepUp interface {
	StepUp(r *http.Request) error
}

// API serves the saved-credential routes.
type API struct {
	svc    *rdpcreds.Service
	stepUp StepUp
}

// New builds the API.
func New(svc *rdpcreds.Service, stepUp StepUp) *API {
	return &API{svc: svc, stepUp: stepUp}
}

// Register mounts the routes. Every route requires a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/devices/{id}/rdp-credentials", a.list)
	r("PUT /api/v1/devices/{id}/rdp-credentials", a.save)
	r("DELETE /api/v1/devices/{id}/rdp-credentials/{credentialId}", a.remove)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	list, err := a.svc.List(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"credentials": list})
	return nil
}

type saveRequest struct {
	Label    string      `json:"label"`
	Domain   string      `json:"domain"`
	Username string      `json:"username"`
	Password secretBytes `json:"password"`
}

func (a *API) save(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in saveRequest
	defer func() { clear(in.Password) }()
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	// Saving needs a second factor within the last 5 minutes (ADR-0055).
	if err := a.stepUp.StepUp(r); err != nil {
		return err
	}
	cr, err := a.svc.Save(r.Context(), httpapi.Caller(r), id, rdpcreds.SaveInput{
		Label: in.Label, Domain: in.Domain, Username: in.Username, Password: in.Password,
	})
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, http.StatusOK, cr)
	return nil
}

func (a *API) remove(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	cid, err := httpapi.PathUUID(r, "credentialId")
	if err != nil {
		return err
	}
	if err := a.stepUp.StepUp(r); err != nil {
		return err
	}
	if err := a.svc.Delete(r.Context(), httpapi.Caller(r), id, cid); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// secretBytes is a JSON string kept as bytes the handler can zero, never
// converted to a Go string.
type secretBytes []byte

var errSecret = errors.New("password must be a JSON string")

// wrongType is what the JSON decoder reports for a password that is not a
// string, so the answer names the field like any other.
var wrongType = &json.UnmarshalTypeError{Value: "non-string", Field: "password", Type: reflect.TypeFor[string]()}

// UnmarshalJSON unquotes the string by hand, as encoding/json would.
func (s *secretBytes) UnmarshalJSON(raw []byte) error {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return wrongType
	}
	raw = raw[1 : len(raw)-1]
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		c := raw[i]
		if c != '\\' {
			out = append(out, c)
			i++
			continue
		}
		if i+1 >= len(raw) {
			return errSecret
		}
		i++
		switch raw[i] {
		case '"', '\\', '/':
			out = append(out, raw[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, n, ok := hex4(raw[i+1:])
			if !ok {
				return errSecret
			}
			i += n
			if utf16.IsSurrogate(r) {
				rest := raw[i+1:]
				if len(rest) >= 6 && rest[0] == '\\' && rest[1] == 'u' {
					if r2, _, ok := hex4(rest[2:]); ok {
						if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
							r = dec
							i += 6
						}
					}
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			return errSecret
		}
		i++
	}
	*s = out
	return nil
}

func hex4(b []byte) (rune, int, bool) {
	if len(b) < 4 {
		return 0, 0, false
	}
	var r rune
	for _, c := range b[:4] {
		r <<= 4
		switch {
		case c >= '0' && c <= '9':
			r |= rune(c - '0')
		case c >= 'a' && c <= 'f':
			r |= rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			r |= rune(c-'A') + 10
		default:
			return 0, 0, false
		}
	}
	return r, 4, true
}
