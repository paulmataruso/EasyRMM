//go:build !windows

package roles

import (
	"context"
	"errors"
)

// Read finds nothing off Windows: the roles are Windows roles.
func Read(context.Context) (Inputs, error) {
	return Inputs{}, errors.New("roles: detection is for Windows")
}
