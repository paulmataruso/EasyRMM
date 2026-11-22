// Package authapi exposes sign-in, MFA, session and password endpoints.
package authapi

import (
	"encoding/base64"
	"encoding/json"
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
	// Security keys and passkeys (ADR-0032).
	mux.Handle("POST /api/v1/auth/passkey/begin", h(a.beginPasskey))
	mux.Handle("POST /api/v1/auth/passkey/finish", h(a.finishPasskey))
	mux.Handle("POST /api/v1/auth/mfa/webauthn/begin", httpapi.RequireState(auth.StateMFARequired)(h(a.beginKeyMFA)))
	mux.Handle("POST /api/v1/auth/mfa/webauthn/finish", httpapi.RequireState(auth.StateMFARequired)(h(a.finishKeyMFA)))
	mux.Handle("GET /api/v1/auth/security-keys", httpapi.RequireActive(h(a.listKeys)))
	mux.Handle("POST /api/v1/auth/security-keys/begin", httpapi.RequireState(auth.StateMFAEnrollment, auth.StateActive)(h(a.beginKey)))
	mux.Handle("POST /api/v1/auth/security-keys/finish", httpapi.RequireState(auth.StateMFAEnrollment, auth.StateActive)(h(a.finishKey)))
	mux.Handle("POST /api/v1/auth/security-keys/{id}/remove", httpapi.RequireActive(h(a.removeKey)))
	mux.Handle("POST /api/v1/auth/passkey-prompt", httpapi.RequireActive(h(a.answerPasskeyPrompt)))
	// The link `easyrmm-server recover` prints (ADR-0044).
	mux.Handle("POST /api/v1/auth/recover", h(a.recover))
}

type recoverRequest struct {
	Token string `json:"token"`
}

// recover signs in with a one-time recovery link from the server's shell.
func (a *API) recover(w http.ResponseWriter, r *http.Request) error {
	var req recoverRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	// Signing in replaces any existing session in this browser.
	if old := httpapi.IdentityFrom(r.Context()); old != nil {
		_ = a.svc.Logout(r.Context(), old.Session, old.User, httpapi.Meta(r))
	}
	token, sess, err := a.svc.RedeemRecoveryLink(r.Context(), strings.TrimSpace(req.Token), httpapi.Meta(r))
	switch {
	case errors.Is(err, auth.ErrRecoveryLinkInvalid):
		return &httpapi.Error{Status: http.StatusBadRequest, Code: "invalid_recovery_link",
			Message: "This link has expired or was already used. Run easyrmm-server recover on the server for a new one."}
	case errors.Is(err, auth.ErrAccountUnavailable):
		return &httpapi.Error{Status: http.StatusForbidden, Code: "account_unavailable", Message: "This account is disabled or locked."}
	case err != nil:
		return mapAuthError(err)
	}
	return a.respondWithToken(w, r, token, sess.ExpiresAt)
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
	case errors.Is(err, auth.ErrWebAuthnUnavailable):
		return &httpapi.Error{Status: http.StatusNotFound, Code: "webauthn_unavailable", Message: "Security keys and passkeys are not available on this server."}
	case errors.Is(err, auth.ErrKeyRejected):
		return &httpapi.Error{Status: http.StatusUnauthorized, Code: "key_rejected", Message: "That security key or passkey was not accepted. Try again, or use another way to sign in."}
	case errors.Is(err, auth.ErrKeyName):
		return httpapi.Validation(map[string]string{"name": fmt.Sprintf("Give the key a name of up to %d characters.", auth.MaxKeyName)})
	case errors.Is(err, auth.ErrKeyNameTaken):
		return httpapi.Validation(map[string]string{"name": "You already have a key with this name."})
	case errors.Is(err, auth.ErrKeyExists):
		return &httpapi.Error{Status: http.StatusConflict, Code: "key_exists", Message: "This security key or passkey is already registered."}
	case errors.Is(err, auth.ErrTooManyKeys):
		return &httpapi.Error{Status: http.StatusConflict, Code: "too_many_keys", Message: fmt.Sprintf("You have %d security keys and passkeys, the most allowed. Remove one first.", auth.MaxSecurityKeys)}
	case errors.Is(err, auth.ErrLastFactor):
		return &httpapi.Error{Status: http.StatusConflict, Code: "last_factor", Message: "This is your only second factor. Add an authenticator app or another key before removing it."}
	case errors.Is(err, auth.ErrKeyNotFound):
		return httpapi.ErrNotFound
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

func (a *API) options(w http.ResponseWriter, r *http.Request) error {
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{
		"passwordResetAvailable": a.svc.ResetAvailable(r.Context()),
		"mfaRequired":            a.svc.Config().RequireMFA,
		"passwordMinLength":      auth.MinPasswordLength,
		"webauthn":               a.svc.WebAuthn(),
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
	var req passwordConfirm
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	enr, err := a.svc.BeginTOTPEnrollment(r.Context(), id.Session, id.User, req.Password, httpapi.Meta(r))
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return httpapi.Validation(map[string]string{"password": "Your password is not correct."})
	}
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
	token, err := a.svc.ChangePassword(r.Context(), id.Session, id.User, req.CurrentPassword, req.NewPassword, httpapi.Meta(r))
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return httpapi.Validation(map[string]string{"currentPassword": "Your current password is not correct."})
	}
	if msg := auth.PasswordAdvice(err); msg != "" {
		return httpapi.Validation(map[string]string{"newPassword": msg})
	}
	if err != nil {
		return mapAuthError(err)
	}
	// The session continues under a new token (and so a new CSRF token).
	return a.respondWithToken(w, r, token, id.Session.ExpiresAt)
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

// credentialRequest carries the browser's answer to a WebAuthn ceremony,
// passed as it came to go-webauthn's parser.
type credentialRequest struct {
	Credential json.RawMessage `json:"credential"`
}

func (c credentialRequest) body() ([]byte, error) {
	if len(c.Credential) == 0 || c.Credential[0] != '{' {
		return nil, httpapi.Validation(map[string]string{"credential": "The browser's answer is missing."}) //nolint:gosec // a field name, not a secret
	}
	return c.Credential, nil
}

func (a *API) beginPasskey(w http.ResponseWriter, r *http.Request) error {
	assertion, err := a.svc.BeginPasskeyLogin(r.Context(), httpapi.Meta(r))
	if err != nil {
		return mapAuthError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, assertion)
	return nil
}

func (a *API) finishPasskey(w http.ResponseWriter, r *http.Request) error {
	var req credentialRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	body, err := req.body()
	if err != nil {
		return err
	}
	token, sess, err := a.svc.FinishPasskeyLogin(r.Context(), body, httpapi.Meta(r))
	if err != nil {
		return mapAuthError(err)
	}
	// Signing in replaces any existing session in this browser.
	if old := httpapi.IdentityFrom(r.Context()); old != nil {
		_ = a.svc.Logout(r.Context(), old.Session, old.User, httpapi.Meta(r))
	}
	return a.respondWithToken(w, r, token, sess.ExpiresAt)
}

func (a *API) beginKeyMFA(w http.ResponseWriter, r *http.Request) error {
	id := httpapi.IdentityFrom(r.Context())
	assertion, err := a.svc.BeginKeyMFA(r.Context(), id.Session)
	if err != nil {
		return mapAuthError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, assertion)
	return nil
}

func (a *API) finishKeyMFA(w http.ResponseWriter, r *http.Request) error {
	var req credentialRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	body, err := req.body()
	if err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	token, err := a.svc.FinishKeyMFA(r.Context(), id.Session, id.User, body, httpapi.Meta(r))
	if err != nil {
		return mapAuthError(err)
	}
	return a.respondWithToken(w, r, token, time.Now().Add(a.svc.Config().MaxSessionAge))
}

func (a *API) listKeys(w http.ResponseWriter, r *http.Request) error {
	id := httpapi.IdentityFrom(r.Context())
	keys, err := a.svc.SecurityKeys(r.Context(), id.User.ID)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"items": keys})
	return nil
}

func (a *API) beginKey(w http.ResponseWriter, r *http.Request) error {
	var req passwordConfirm
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	creation, err := a.svc.BeginKeyRegistration(r.Context(), id.Session, req.Password, httpapi.Meta(r))
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return httpapi.Validation(map[string]string{"password": "Your password is not correct."})
	}
	if err != nil {
		return mapAuthError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, creation)
	return nil
}

type passkeyPromptAnswer struct {
	// Answer is "later" (ask again in 30 days) or "never".
	Answer string `json:"answer"`
}

func (a *API) answerPasskeyPrompt(w http.ResponseWriter, r *http.Request) error {
	var req passkeyPromptAnswer
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	if req.Answer != "later" && req.Answer != "never" {
		return httpapi.Validation(map[string]string{"answer": `Answer "later" or "never".`})
	}
	id := httpapi.IdentityFrom(r.Context())
	if err := a.svc.AnswerPasskeyPrompt(r.Context(), id.Session, req.Answer == "never"); err != nil {
		return mapAuthError(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type finishKeyRequest struct {
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func (a *API) finishKey(w http.ResponseWriter, r *http.Request) error {
	var req finishKeyRequest
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	body, err := credentialRequest{Credential: req.Credential}.body()
	if err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	added, err := a.svc.FinishKeyRegistration(r.Context(), id.Session, id.User, req.Name, body, httpapi.Meta(r))
	if err != nil {
		return mapAuthError(err)
	}
	token := id.Token
	if added.Token != "" {
		token = added.Token
		a.sessions.SetCookie(w, token, time.Now().Add(a.svc.Config().MaxSessionAge))
	}
	sess, user, err := a.svc.Authenticate(r.Context(), token)
	if err != nil {
		return err
	}
	view := &httpapi.Identity{Session: sess, User: user, CSRFToken: a.sessions.CSRFToken(token)}
	p, err := a.svc.LoadPrincipal(r.Context(), user.ID)
	if err != nil {
		return err
	}
	view.Principal = p
	codes := added.RecoveryCodes
	if codes == nil {
		codes = []string{}
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"key": added.Key, "recoveryCodes": codes, "session": a.view(view)})
	return nil
}

func (a *API) removeKey(w http.ResponseWriter, r *http.Request) error {
	keyID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return httpapi.ErrNotFound
	}
	var req passwordConfirm
	if err := httpapi.DecodeJSON(w, r, &req); err != nil {
		return err
	}
	id := httpapi.IdentityFrom(r.Context())
	err = a.svc.RemoveSecurityKey(r.Context(), id.Session, id.User, keyID, req.Password, httpapi.Meta(r))
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return httpapi.Validation(map[string]string{"password": "Your password is not correct."})
	}
	if err != nil {
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
