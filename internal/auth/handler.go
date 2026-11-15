package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/paulmataruso/easyrm/internal/config"
	"github.com/paulmataruso/easyrm/pkg/models"
)

type Handler struct {
	store *Store
	cfg   config.AuthConfig
}

func NewHandler(store *Store, cfg config.AuthConfig) *Handler {
	return &Handler{store: store, cfg: cfg}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Post("/login", h.Login)
	r.Post("/logout", h.Logout)
	r.Get("/me", h.Me)
	r.Put("/password", h.ChangePassword)
	r.Post("/mfa/setup", h.MFASetup)
	r.Post("/mfa/verify", h.MFAVerify)
	r.Post("/mfa/disable", h.MFADisable)
	return r
}

const sessionCookieName = "__Host-session"

// --- Login ---

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type loginResponse struct {
	User       *models.User `json:"user"`
	MFARequired bool        `json:"mfa_required,omitempty"`
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	user, err := h.store.GetUserByUsername(r.Context(), req.Username)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		slog.Error("login: get user", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if !user.IsActive {
		writeError(w, http.StatusForbidden, "account is disabled")
		return
	}

	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		writeError(w, http.StatusTooManyRequests, "account is temporarily locked")
		return
	}

	match, err := VerifyPassword(user.PasswordHash, req.Password)
	if err != nil {
		slog.Error("login: verify password", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !match {
		_ = h.store.IncrementFailedLogins(r.Context(), user.ID)
		h.auditLogin(r, user, false, "invalid password")
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if user.MFAEnabled {
		if req.MFACode == "" {
			writeJSON(w, http.StatusOK, loginResponse{MFARequired: true})
			return
		}
		if !ValidateMFACode(user.MFASecret, req.MFACode) {
			_ = h.store.IncrementFailedLogins(r.Context(), user.ID)
			h.auditLogin(r, user, false, "invalid mfa code")
			writeError(w, http.StatusUnauthorized, "invalid MFA code")
			return
		}
	}

	_ = h.store.ResetFailedLogins(r.Context(), user.ID)
	_ = h.store.UpdateLastLogin(r.Context(), user.ID)

	token, tokenHash, err := GenerateSessionToken()
	if err != nil {
		slog.Error("login: generate token", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	_, err = h.store.CreateSession(r.Context(), user.ID, tokenHash, clientIP(r), r.UserAgent(), h.cfg.SessionDuration)
	if err != nil {
		slog.Error("login: create session", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.cfg.SessionDuration.Seconds()),
	})

	h.auditLogin(r, user, true, "")
	writeJSON(w, http.StatusOK, loginResponse{User: user})
}

// --- Logout ---

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil && cookie.Value != "" {
		tokenHash := HashToken(cookie.Value)
		sess, err := h.store.GetSessionByToken(r.Context(), tokenHash)
		if err == nil {
			_ = h.store.DeleteSession(r.Context(), sess.ID)
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// --- Me ---

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// --- Change Password ---

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}

	if len(req.NewPassword) < 12 {
		writeError(w, http.StatusBadRequest, "new password must be at least 12 characters")
		return
	}

	dbUser, err := h.store.GetUserByID(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	match, err := VerifyPassword(dbUser.PasswordHash, req.CurrentPassword)
	if err != nil || !match {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	newHash, err := HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := h.store.UpdatePassword(r.Context(), user.ID, newHash); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	h.audit(r, user, "password_changed", "user", user.ID.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "password changed"})
}

// --- MFA Setup ---

type mfaSetupResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

func (h *Handler) MFASetup(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	if user.MFAEnabled {
		writeError(w, http.StatusConflict, "MFA is already enabled")
		return
	}

	secret, url, err := GenerateMFASecret(user.Username)
	if err != nil {
		slog.Error("mfa setup: generate", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, mfaSetupResponse{Secret: secret, OTPAuthURL: url})
}

// --- MFA Verify (enable) ---

type mfaVerifyRequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

func (h *Handler) MFAVerify(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req mfaVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !ValidateMFACode(req.Secret, req.Code) {
		writeError(w, http.StatusBadRequest, "invalid verification code")
		return
	}

	if err := h.store.SetMFASecret(r.Context(), user.ID, req.Secret); err != nil {
		slog.Error("mfa verify: set secret", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	h.audit(r, user, "mfa_enabled", "user", user.ID.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa enabled"})
}

// --- MFA Disable ---

type mfaDisableRequest struct {
	Password string `json:"password"`
}

func (h *Handler) MFADisable(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	var req mfaDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	dbUser, err := h.store.GetUserByID(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	match, err := VerifyPassword(dbUser.PasswordHash, req.Password)
	if err != nil || !match {
		writeError(w, http.StatusUnauthorized, "incorrect password")
		return
	}

	if err := h.store.DisableMFA(r.Context(), user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	h.audit(r, user, "mfa_disabled", "user", user.ID.String(), nil)
	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa disabled"})
}

// --- Helpers ---

func (h *Handler) auditLogin(r *http.Request, user *models.User, success bool, reason string) {
	details := map[string]any{"success": success}
	if reason != "" {
		details["reason"] = reason
	}
	action := "login_success"
	if !success {
		action = "login_failed"
	}
	h.audit(r, user, action, "session", "", details)
}

func (h *Handler) audit(r *http.Request, user *models.User, action, resourceType, resourceID string, details map[string]any) {
	log := models.AuditLog{
		UserID:       &user.ID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
		IPAddress:    clientIP(r),
		UserAgent:    r.UserAgent(),
	}
	if err := h.store.CreateAuditLog(r.Context(), log); err != nil {
		slog.Error("audit log failed", "action", action, "error", err)
	}
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	if real := r.Header.Get("X-Real-IP"); real != "" {
		return real
	}
	host := r.RemoteAddr
	// Strip port
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
