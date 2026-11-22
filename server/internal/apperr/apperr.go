// Package apperr defines the errors domain services return to describe
// outcomes the caller should see (invalid input, missing objects, denied
// access, conflicts). The HTTP layer maps them to status codes; anything else
// is treated as an internal error and never shown to clients.
package apperr

import (
	"errors"
	"maps"
)

// Kind classifies an error.
type Kind uint8

// Kinds.
const (
	KindInvalid     Kind = iota + 1 // the request is malformed or fails validation
	KindNotFound                    // the object does not exist or is outside the caller's scope
	KindForbidden                   // the caller may see the object but not perform the action
	KindConflict                    // the request conflicts with current state
	KindUnavailable                 // a dependency the request needs is temporarily unavailable
	KindTooMany                     // the caller has reached a limit; trying later may succeed
)

// Error is a user-facing error.
type Error struct {
	Kind    Kind
	Code    string
	Message string
	Fields  map[string]string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Is matches errors of the same kind and code, so callers can compare with
// errors.Is against the sentinels below or values built by Conflict.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Kind == e.Kind && t.Code == e.Code
}

// Sentinels for errors.Is.
var (
	ErrNotFound  = &Error{Kind: KindNotFound, Code: "not_found", Message: "The requested item does not exist or you do not have access to it."}
	ErrForbidden = &Error{Kind: KindForbidden, Code: "forbidden", Message: "You do not have permission to do that."}
	ErrInvalid   = &Error{Kind: KindInvalid, Code: "validation_failed", Message: "Some fields need attention."}
)

// NotFound returns the generic not-found error. Services return it both for
// missing objects and for objects outside the caller's scope, so existence
// is never revealed across tenants.
func NotFound() error { return ErrNotFound }

// Forbidden returns the generic permission error.
func Forbidden() error { return ErrForbidden }

// Conflict builds a conflict error with a stable code.
func Conflict(code, msg string) *Error {
	return &Error{Kind: KindConflict, Code: code, Message: msg}
}

// Unavailable builds an error for a dependency that is down, such as the
// remote-access server.
func Unavailable(code, msg string) *Error {
	return &Error{Kind: KindUnavailable, Code: code, Message: msg}
}

// TooMany builds an error for a limit the caller has reached, with a
// stable code and a message that says when to try again.
func TooMany(code, msg string) *Error {
	return &Error{Kind: KindTooMany, Code: code, Message: msg}
}

// Invalid builds a validation error for a single field.
func Invalid(field, msg string) *Error {
	return &Error{Kind: KindInvalid, Code: ErrInvalid.Code, Message: ErrInvalid.Message, Fields: map[string]string{field: msg}}
}

// Fields accumulates validation problems.
type Fields map[string]string

// Add records a problem with a field, keeping the first one reported.
func (f Fields) Add(field, msg string) {
	if _, ok := f[field]; !ok {
		f[field] = msg
	}
}

// Check records msg against field when ok is false.
func (f Fields) Check(ok bool, field, msg string) {
	if !ok {
		f.Add(field, msg)
	}
}

// Err returns a validation error, or nil when no problems were recorded.
func (f Fields) Err() error {
	if len(f) == 0 {
		return nil
	}
	return &Error{Kind: KindInvalid, Code: ErrInvalid.Code, Message: ErrInvalid.Message, Fields: maps.Clone(f)}
}

// As extracts an *Error.
func As(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}
