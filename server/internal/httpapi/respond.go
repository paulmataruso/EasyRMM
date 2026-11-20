// Package httpapi contains the HTTP plumbing shared by every API module:
// JSON encoding and decoding, error responses, security middleware, client
// address resolution, session authentication and CSRF protection.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

// MaxJSONBody bounds request bodies for ordinary JSON endpoints.
const MaxJSONBody = 1 << 20 // 1 MiB

// ErrorBody is the JSON error envelope: {"error":{"code":"…","message":"…"}}.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail describes an error. Fields maps request fields to problems for
// validation errors.
type ErrorDetail struct {
	Code    string            `json:"code"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// Error is an error with an HTTP status and a stable machine-readable code.
type Error struct {
	Status  int
	Code    string
	Message string
	Fields  map[string]string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Common errors.
var (
	ErrUnauthenticated = &Error{Status: http.StatusUnauthorized, Code: "unauthenticated", Message: "Sign in to continue."}
	ErrForbidden       = &Error{Status: http.StatusForbidden, Code: "forbidden", Message: "You do not have permission to do that."}
	ErrNotFound        = &Error{Status: http.StatusNotFound, Code: "not_found", Message: "The requested item does not exist or you do not have access to it."}
	ErrCSRF            = &Error{Status: http.StatusForbidden, Code: "csrf_failed", Message: "The request could not be verified. Reload the page and try again."}
	ErrTooMany         = &Error{Status: http.StatusTooManyRequests, Code: "rate_limited", Message: "Too many attempts. Wait a moment and try again."}
)

// Validation builds a 422 error with per-field messages.
func Validation(fields map[string]string) *Error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: "validation_failed", Message: "Some fields need attention.", Fields: fields}
}

// BadRequest builds a 400 error.
func BadRequest(msg string) *Error {
	return &Error{Status: http.StatusBadRequest, Code: "bad_request", Message: msg}
}

// Conflict builds a 409 error.
func Conflict(code, msg string) *Error {
	return &Error{Status: http.StatusConflict, Code: code, Message: msg}
}

// WriteJSON writes v as JSON with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

// StatusClientClosedRequest is recorded for a request whose client went away
// before it completed: nginx's 499, so access logs read the same.
const StatusClientClosedRequest = 499

// WriteError writes err as a JSON error. Unknown errors become a generic 500
// whose details are logged, never returned to the client.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *Error
	if errors.As(err, &apiErr) {
		WriteJSON(w, apiErr.Status, ErrorBody{Error: ErrorDetail{Code: apiErr.Code, Message: apiErr.Message, Fields: apiErr.Fields}})
		return
	}
	if ae, ok := apperr.As(err); ok {
		status := http.StatusInternalServerError
		switch ae.Kind {
		case apperr.KindInvalid:
			status = http.StatusUnprocessableEntity
		case apperr.KindNotFound:
			status = http.StatusNotFound
		case apperr.KindForbidden:
			status = http.StatusForbidden
		case apperr.KindConflict:
			status = http.StatusConflict
		case apperr.KindUnavailable:
			status = http.StatusServiceUnavailable
		}
		if status != http.StatusInternalServerError {
			WriteJSON(w, status, ErrorBody{Error: ErrorDetail{Code: ae.Code, Message: ae.Message, Fields: ae.Fields}})
			return
		}
	}
	// The client went away (a closed tab, a navigation) and the work stopped
	// with it: nothing failed on the server.
	if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
		LoggerFrom(r.Context()).Info("request canceled by the client", "method", r.Method, "path", LogSafe(r.URL.Path))
		WriteJSON(w, StatusClientClosedRequest, nil)
		return
	}
	LoggerFrom(r.Context()).Error("request failed", "error", err, "method", r.Method, "path", LogSafe(r.URL.Path))
	WriteJSON(w, http.StatusInternalServerError, ErrorBody{Error: ErrorDetail{
		Code: "internal_error", Message: "Something went wrong on the server. The error has been logged.",
	}})
}

// DecodeJSON strictly decodes a JSON request body into dst: the content type
// must be JSON, unknown fields are rejected, the body is size-limited and
// must contain exactly one value.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	ct := r.Header.Get("Content-Type")
	if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/json" {
		return &Error{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Send the request body as application/json."}
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxJSONBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		var syntaxErr *json.SyntaxError
		var typeErr *json.UnmarshalTypeError
		switch {
		case errors.As(err, &maxErr):
			return &Error{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Message: "The request body is too large."}
		case errors.Is(err, io.EOF):
			return BadRequest("The request body is empty.")
		case errors.As(err, &syntaxErr), errors.Is(err, io.ErrUnexpectedEOF):
			return BadRequest("The request body is not valid JSON.")
		case errors.As(err, &typeErr) && typeErr.Field == "":
			return BadRequest("The request body must be a JSON object.")
		case errors.As(err, &typeErr):
			return Validation(map[string]string{typeErr.Field: "has the wrong type"})
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
			return Validation(map[string]string{field: "is not a recognized field"})
		default:
			return BadRequest(fmt.Sprintf("The request body could not be read: %v", err))
		}
	}
	if dec.More() {
		return BadRequest("The request body must contain a single JSON value.")
	}
	return nil
}

// HandlerFunc is an http.HandlerFunc that returns an error; the error is
// rendered with WriteError.
type HandlerFunc func(w http.ResponseWriter, r *http.Request) error

// Handle adapts a HandlerFunc.
func Handle(h HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h(w, r); err != nil {
			WriteError(w, r, err)
		}
	})
}

type loggerKey struct{}

// LogSafe returns s, something a client sent such as a request's path, with
// its line breaks escaped, for a log line: whoever reads the log as plain
// text must not take a line the client wrote for one of the server's.
func LogSafe(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", `\r`), "\n", `\n`)
}

// LoggerFrom returns the request-scoped logger, or the default logger.
func LoggerFrom(ctx interface{ Value(any) any }) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}
