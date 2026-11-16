//go:build !linux && !windows

package easypatch

import (
	"context"
	"errors"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func platform() System { return unsupported{} }

type unsupported struct{}

var errUnsupported = errors.New("EasyRMM installs the EasyPatch agent on Windows and Linux only")

func (unsupported) Formats() ([]string, error) { return nil, errUnsupported }

func (unsupported) Install(context.Context, *agentproto.EasyPatchInstallPayload, agentproto.EasyPatchPackage, string) error {
	return errUnsupported
}

func (unsupported) Enroll(context.Context, *agentproto.EasyPatchInstallPayload) error { return errUnsupported }
