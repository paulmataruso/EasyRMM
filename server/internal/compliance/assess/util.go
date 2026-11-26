package assess

import (
	"strings"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
)

func trim(s string) string { return strings.TrimSpace(s) }

// nilUser is the caller's user id, or nil for the system.
func nilUser(c access.Caller) *uuid.UUID {
	if c.Actor.ID == uuid.Nil {
		return nil
	}
	id := c.Actor.ID
	return &id
}
