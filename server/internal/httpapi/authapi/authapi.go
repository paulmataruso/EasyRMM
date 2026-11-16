// Package authapi exposes sign-in, MFA, session and password endpoints.
package authapi

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/boombuler/barcode/qr"
	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// API serves /api/v1/auth.
type API struct {
	svc      *auth.Service
	sessions *httpapi.Sessions
	features Features
}

// Features are the optional parts of the server that are switched on.
type Features struct {
	// RemoteAccess is MeshCentral remote access (EASYRMM_MESH_ENABLED).
	RemoteAccess bool `json:"remoteAccess"`
}

// New builds the auth API.
func New(svc *auth.Service, sessions *httpapi.Sessions, features Features) *API {
	return &API{svc: svc, sessions: sessions, features: features}
}

// Register mounts the routes.
func (a *API) Register(mux *http.ServeMux) {
	h := httpapi.Handle
	mux.Handle("GET /api/v1/auth/options", h(a.options))
	mux.Handle("POST /api/v1/auth/login", h(a.login))
	mux.Handle("GET /api/v1/auth/session", h(a.session))
	mux.Handle("POST /api/v1/auth/logout", h(a.logout))
	mux.Handle("POST /api/v1/auth/mfa/verify", httpapi.RequireState(auth.StateMFARequired)(h(a.verifyMFA)))
	mux.Handle("POST /api/v1/auth/mfa/totp/begin", httpapi.RequireState(auth.StateMFAEnrollment, auth.StateActive)(h(a.beginTOTP)))
	mux.Handle("POST /api/v1/auth/mfa/totp/confirm", httpapi.RequireState(auth.StateMFAEnrollment, auth.StateActive)(h(a.confirmTOTP)))
	mux.Handle("POST /api/v1/auth/mfa/recovery-codes", httpapi.RequireActive(h(a.regenerateCodes)))
	mux.Handle("POST /api/v1/auth/password", httpapi.RequireActive(h(a.changePassword)))
	mux.Handle("GET /api/v1/auth/sessions", httpapi.RequireActive(h(a.listSessions)))
	mux.Handle("DELETE /api/v1/auth/sessions/{id}", httpapi.RequireActive(h(a.revokeSession)))
	mux.Handle("POST /api/v1/auth/password-reset/request", h(a.requestReset))
	mux.Handle("POST /api/v1/auth/password-reset/complete", h(a.completeReset))
}

func mapAuthError(err error) error {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		return &httpapi.Error{Status: http.StatusUnauthorized, Code: "invalid_credentials", Message: "Sign-in failed. Check your email and password, or wait a few minutes if you have tried several times."}
	case errors.Is(err, auth.ErrRateLimited):
		return httpapi.ErrTooMany
	case errors.Is(err, auth.ErrInvalidCode):
		return &httpapi.Error{Status: http.StatusUnauthorized, Code: "invalid_code", Message: "That code is not valid. Codes change every 30 seconds; try the current one."}
	case errors.Is(err, auth.ErrWrongState):
		return &httpapi.Error{Status: http.StatusConflict, Code: "wrong_state", Message: "This step is not available right now. Reload the page."}
	case errors.Is(err, auth.ErrInvalidSession):
		return httpapi.ErrNotFound
	case errors.Is(err, auth.ErrInvalidResetToken):
		return &httpapi.Error{Status: http.StatusBadRequest, Code: "invalid_reset_token", Message: "This reset link is invalid or has expired. Request a new one."}
	case errors.Is(err, auth.ErrResetUnavailable):
		return &httpapi.Error{Status: http.StatusNotFound, Code: "reset_unavailable", Message: "Email is not configured on this server. Ask an administrator for a reset link."}
	}
	if msg := auth.PasswordAdvice(err); msg != "" {
		return httpapi.Validation(map[string]string{"password": msg})
	}
	return err
}

// SessionView describes the current sign-in state to the browser.
type SessionView struct {
	State       auth.SessionState `json:"state"`
	User        *auth.User        `json:"user"`
	CSRFToken   string            `json:"csrfToken"`
	ExpiresAt   time.Time         `json:"expiresAt"`
	Permissions []rbac.Permission `json:"permissions"`
	// GlobalPermissions are those held platform-wide, not only in some
	// organizations or sites.
	GlobalPermissions []rbac.Permission `json:"globalPermissions"`
	IsSuperAdmin      bool              `json:"isSuperAdmin"`
	Features          Features          `json:"features"`
}

func (a *API) view(id *httpapi.Identity) SessionView {
	v := SessionView{State: id.Session.State, User: id.User, CSRFToken: id.CSRFToken, ExpiresAt: id.Session.ExpiresAt,
		Permissions: []rbac.Permission{}, GlobalPermissions: []rbac.Permission{}, Features: a.features}
	if id.Principal != nil {
		v.Permissions = id.Principal.Permissions()
		v.GlobalPermissions = id.Principal.GlobalPermissions()
		v.IsSuperAdmin = id.Principal.IsSuperAdmin()
	}
	return v
}

func (a *API) options(w http.ResponseWriter, _ *http.Request) error {
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{
		"passwordResetAvailable": a.svc.ResetAvailable(),
		"mfaRequired":            a.svc.Config().RequireMFA,
		"passwordMinLength":      auth.MinPasswordLength,
	})
	return nil
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *API) login(w http.ResponseWriter, r *http.Request) error {
	var req loginRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Email) == "" || req.Password == "" {
		return httpapi.Validation(map[string]string{"email": "Enter your email and password."})
	}
	// Signing in replaces any existing session in this browser.
	if old := httpapi.IdentityFrom(r.Context()); old != nil {
		_ = a.svc.Logout(r.Context(), old.Session, old.User, httpapi.Meta(r))
	}
	token, sess, err := a.svc.Login(r.Context(), req.Email, req.Password, httpapi.Meta(r))
	if err != nil {
		return mapAuthError(err)
	}
	return a.respondWithToken(w, r, token, sess.ExpiresAt)
}

// respondWithToken sets the cookie for a new or rotated token and returns
// the resulting session view.
func (a *API) respondWithToken(w http.ResponseWriter, r *http.Request, token string, expires time.Time) error {
	sess, user, err := a.svc.Authenticate(r.Context(), token)
	if err != nil {
		return err
	}
	id := &httpapi.Identity{Token: token, Session: sess, User: user, CSRFToken: a.sessions.CSRFToken(token)}
	if sess.State == auth.StateActive {
		p, err := a.svc.LoadPrincipal(r.Context(), user.ID)
		if err != nil {
			return err
		}
		id.Principal = p
	}
	a.sessions.SetCookie(w, token, expires)
	httpapi.WriteJSON(w, http.StatusOK, a.view(id))
	return nil
}

func (a *API) session(w http.ResponseWriter, r *http.Request) error {
	id := httpapi.IdentityFrom(r.Context())
	if id == nil {
		return httpapi.ErrUnauthenticated
	}
	httpapi.WriteJSON(w, http.StatusOK, a.view(id))
	return nil
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) error {
	if id := httpapi.IdentityFrom(r.Context()); id != nil {
		if err := a.svc.Logout(r.Context(), id.Session, id.User, httpapi.Meta(r)); err != nil {
			return err
		}
	}
	a.sessions.ClearCookie(w)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type codeRequest struct {
	Code string `json:"code"`
}

func (a *API) verifyMFA(w http.ResponseWriter, r *http.Request) error {
	var req codeRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	token, err := a.svc.VerifyMFA(r.Context(), id.Session, id.User, req.Code, httpapi.Meta(r))
	if err != nil {
		return mapAuthError(err)
	}
	return a.respondWithToken(w, r, token, time.Now().Add(a.svc.Config().MaxSessionAge))
}

type enrollmentView struct {
	Secret    string `json:"secret"`
	URI       string `json:"uri"`
	QRCodeSVG string `json:"qrCodeSvg"`
}

func (a *API) beginTOTP(w http.ResponseWriter, r *http.Request) error {
	id := httpapi.IdentityFrom(r.Context())
	enr, err := a.svc.BeginTOTPEnrollment(r.Context(), id.Session, id.User)
	if err != nil {
		return mapAuthError(err)
	}
	svg, err := qrSVG(enr.URI)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, enrollmentView{Secret: enr.Secret, URI: enr.URI, QRCodeSVG: svg})
	return nil
}

func (a *API) confirmTOTP(w http.ResponseWriter, r *http.Request) error {
	var req codeRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	codes, token, err := a.svc.ConfirmTOTPEnrollment(r.Context(), id.Session, id.User, req.Code, httpapi.Meta(r))
	if err != nil {
		return mapAuthError(err)
	}
	if token == "" {
		token = id.Token
	} else {
		a.sessions.SetCookie(w, token, time.Now().Add(a.svc.Config().MaxSessionAge))
	}
	sess, user, err := a.svc.Authenticate(r.Context(), token)
	if err != nil {
		return err
	}
	view := &httpapi.Identity{Session: sess, User: user, CSRFToken: a.sessions.CSRFToken(token)}
	if p, err := a.svc.LoadPrincipal(r.Context(), user.ID); err == nil {
		view.Principal = p
	} else {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes, "session": a.view(view)})
	return nil
}

type passwordConfirm struct {
	Password string `json:"password"`
}

func (a *API) regenerateCodes(w http.ResponseWriter, r *http.Request) error {
	var req passwordConfirm
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	codes, err := a.svc.RegenerateRecoveryCodes(r.Context(), id.Session, id.User, req.Password, httpapi.Meta(r))
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return httpapi.Validation(map[string]string{"password": "Your password is not correct."})
	}
	if err != nil {
		return mapAuthError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"recoveryCodes": codes})
	return nil
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) error {
	var req changePasswordRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	err := a.svc.ChangePassword(r.Context(), id.Session, id.User, req.CurrentPassword, req.NewPassword, httpapi.Meta(r))
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return httpapi.Validation(map[string]string{"currentPassword": "Your current password is not correct."})
	}
	if msg := auth.PasswordAdvice(err); msg != "" {
		return httpapi.Validation(map[string]string{"newPassword": msg})
	}
	if err != nil {
		return mapAuthError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) listSessions(w http.ResponseWriter, r *http.Request) error {
	id := httpapi.IdentityFrom(r.Context())
	list, err := a.svc.ListSessions(r.Context(), id.User.ID)
	if err != nil {
		return err
	}
	type item struct {
		auth.Session
		Current bool `json:"current"`
	}
	out := make([]item, 0, len(list))
	for _, s := range list {
		out = append(out, item{Session: s, Current: s.ID == id.Session.ID})
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
	return nil
}

func (a *API) revokeSession(w http.ResponseWriter, r *http.Request) error {
	sid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return httpapi.ErrNotFound
	}
	id := httpapi.IdentityFrom(r.Context())
	if err := a.svc.RevokeSession(r.Context(), httpapi.Actor(r), id.User.ID, sid); err != nil {
		return mapAuthError(err)
	}
	if sid == id.Session.ID {
		a.sessions.ClearCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type resetRequest struct {
	Email string `json:"email"`
}

func (a *API) requestReset(w http.ResponseWriter, r *http.Request) error {
	var req resetRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	if err := a.svc.RequestPasswordReset(r.Context(), req.Email, httpapi.Meta(r)); err != nil {
		if errors.Is(err, auth.ErrResetUnavailable) || errors.Is(err, auth.ErrRateLimited) {
			return mapAuthError(err)
		}
		// Do not reveal delivery failures or whether the account exists.
		httpapi.LoggerFrom(r.Context()).Error("password reset request failed", "error", err)
	}
	httpapi.WriteJSON(w, http.StatusAccepted, map[string]string{
		"message": "If that address belongs to an account, a reset link is on its way.",
	})
	return nil
}

type completeResetRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (a *API) completeReset(w http.ResponseWriter, r *http.Request) error {
	var req completeResetRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	if err := a.svc.CompletePasswordReset(r.Context(), req.Token, req.Password, httpapi.Meta(r)); err != nil {
		return mapAuthError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// qrSVG renders content as a QR code in an SVG data URL, so the browser
// needs no QR library and the secret never leaves our origin.
func qrSVG(content string) (string, error) {
	code, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return "", fmt.Errorf("encoding qr code: %w", err)
	}
	n := code.Bounds().Dx()
	const quiet = 4
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges">`, n+2*quiet, n+2*quiet)
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" fill="#fff"/><path fill="#000" d="`)
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if rr, _, _, _ := code.At(x, y).RGBA(); rr == 0 {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(b.String())), nil
}
