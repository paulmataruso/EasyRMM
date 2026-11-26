package jobs

import (
	"context"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// NativeHandler runs one native action (agentproto.ShellNative, ADR-0073 as
// amended by ADR-0081): agent code instead of a script, for an action whose
// secret no script's output, transcript or pipe may hold. It receives the
// job's params (verified against the signed hash) and returns the one result
// line a script would print, which never carries a secret.
type NativeHandler func(ctx context.Context, params []byte) string

// WithNative wraps an executor so that a native job runs the handler its
// Script names and everything else runs as before. A handler this build does
// not have fails the run with a plain reason; it never falls back to running
// the name as a script.
func WithNative(next func(context.Context, agentproto.JobPayload, string) agentproto.ResultRequest, handlers map[string]NativeHandler) func(context.Context, agentproto.JobPayload, string) agentproto.ResultRequest {
	return func(ctx context.Context, p agentproto.JobPayload, workRoot string) agentproto.ResultRequest {
		if p.Shell != agentproto.ShellNative {
			return next(ctx, p, workRoot)
		}
		res := agentproto.ResultRequest{StartedAt: time.Now().UTC()}
		h, ok := handlers[p.Script]
		if !ok {
			res.Status, res.Error, res.FinishedAt = agentproto.RunFailed, "This agent has no handler for that native action.", time.Now().UTC()
			return res
		}
		ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutSeconds)*time.Second)
		defer cancel()
		out := h(ctx, p.Params)
		res.FinishedAt = time.Now().UTC()
		switch {
		case ctx.Err() != nil && ctx.Err() == context.DeadlineExceeded:
			res.Status, res.Error = agentproto.RunTimedOut, "The action ran out of time."
		case ctx.Err() != nil:
			res.Status, res.Error = agentproto.RunFailed, "The action was stopped."
		default:
			zero := 0
			res.Status, res.ExitCode, res.Stdout = agentproto.RunSucceeded, &zero, out
		}
		return res
	}
}
