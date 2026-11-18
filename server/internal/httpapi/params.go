package httpapi

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

// PathID parses the {id} path parameter. Malformed identifiers are reported
// as not found, like identifiers that do not exist.
func PathID(r *http.Request) (uuid.UUID, error) {
	return PathUUID(r, "id")
}

// PathUUID parses a named UUID path parameter.
func PathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, apperr.NotFound()
	}
	return id, nil
}

// QueryID parses an optional UUID query parameter; uuid.Nil means absent.
func QueryID(r *http.Request, name string) (uuid.UUID, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return uuid.Nil, nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return uuid.Nil, apperr.Invalid(name, "must be an identifier")
	}
	return id, nil
}

// QueryInt parses an optional integer query parameter within [lo, hi],
// returning def when absent.
func QueryInt(r *http.Request, name string, def, lo, hi int64) (int64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < lo || n > hi {
		return 0, apperr.Invalid(name, "must be a whole number between "+strconv.FormatInt(lo, 10)+" and "+strconv.FormatInt(hi, 10))
	}
	return n, nil
}

// QueryCount parses an optional count query parameter (a page size, a page
// number, a number of days) within [lo, hi], returning def when absent. Counts
// fit in 32 bits, so they convert to int on every platform; use QueryInt for
// wider values such as cursors.
func QueryCount(r *http.Request, name string, def, lo, hi int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 32)
	if err != nil || n < int64(lo) || n > int64(hi) {
		return 0, apperr.Invalid(name, "must be a whole number between "+strconv.Itoa(lo)+" and "+strconv.Itoa(hi))
	}
	return int(n), nil
}

// List is the envelope for collection responses.
type List[T any] struct {
	Items []T `json:"items"`
	// Next is an opaque cursor for the following page, when there is one.
	Next string `json:"next,omitempty"`
}
