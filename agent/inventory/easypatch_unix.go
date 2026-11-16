//go:build !windows

package inventory

import (
	"context"
	"os"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// easyPatchBinary is where the EasyPatch agent's .deb and .rpm install it.
const easyPatchBinary = "/opt/easypatch/easypatch-agent"

// easyPatch reports the EasyPatch agent, nil when it is not installed.
func (c Collector) easyPatch(ctx context.Context) *agentproto.EasyPatchAgent {
	st, err := os.Stat(c.path(easyPatchBinary))
	if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		return nil
	}
	return c.easyPatchStatus(ctx, c.path(easyPatchBinary))
}
