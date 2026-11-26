package tlsapi

import (
	"errors"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
)

func TestErrorsAreTranslated(t *testing.T) {
	at := time.Date(2026, 11, 26, 13, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		err    error
		status int
		code   string
		field  string
	}{
		{tlscert.ErrHeld, 409, "held", ""},
		{tlscert.ErrBusy, 409, "busy", ""},
		{tlscert.ErrNoAccount, 409, "no_account", ""},
		{&tlscert.RefusedError{Reason: "too many", RetryAt: at}, 409, "attempt_refused", "2026-11-26T13:00:00Z"},
		{&tlscert.RefusedError{Reason: "not due"}, 409, "attempt_refused", ""},
		{&tlscert.ErrTooSoon{RetryAfter: 4 * time.Second}, 429, "check_rate_limited", ""},
	} {
		var he *httpapi.Error
		if !errors.As(mapErr(c.err), &he) || he.Status != c.status || he.Code != c.code || he.Fields["retryAt"] != c.field {
			t.Errorf("%v: %+v", c.err, he)
		}
	}
	if !errors.Is(mapErr(tlscert.ErrNoName), apperr.ErrNotFound) {
		t.Error("an unknown name is not found")
	}
	other := errors.New("boom")
	if mapErr(other) != other {
		t.Error("other errors pass through")
	}
}
