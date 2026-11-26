package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

func nativeJob(handler string) agentproto.JobPayload {
	return agentproto.JobPayload{Shell: agentproto.ShellNative, Script: handler, Params: []byte(`{"a":1}`), TimeoutSeconds: 5}
}

func TestNativeRunsTheNamedHandlerAndOthersFallThrough(t *testing.T) {
	var gotParams string
	fell := false
	next := func(context.Context, agentproto.JobPayload, string) agentproto.ResultRequest {
		fell = true
		return agentproto.ResultRequest{Status: agentproto.RunSucceeded}
	}
	run := WithNative(next, map[string]NativeHandler{"x.y": func(_ context.Context, p []byte) string {
		gotParams = string(p)
		return agentproto.NativeResult(1, map[string]int{"n": 1}, "", "")
	}})
	res := run(context.Background(), nativeJob("x.y"), t.TempDir())
	if res.Status != agentproto.RunSucceeded || res.ExitCode == nil || *res.ExitCode != 0 || gotParams != `{"a":1}` || fell {
		t.Fatalf("native: %+v %q fell=%v", res, gotParams, fell)
	}
	if res.Stdout == "" || res.StartedAt.IsZero() || res.FinishedAt.IsZero() {
		t.Fatalf("no result line or times: %+v", res)
	}
	// A script goes the way it always went.
	run(context.Background(), agentproto.JobPayload{Shell: agentproto.ShellSh, Script: "true"}, t.TempDir())
	if !fell {
		t.Fatal("a script did not reach the script executor")
	}
	// A handler this build does not have fails; the name is never run as a script.
	fell = false
	res = run(context.Background(), nativeJob("nope.nope"), t.TempDir())
	if res.Status != agentproto.RunFailed || res.Error == "" || fell {
		t.Fatalf("unknown handler: %+v fell=%v", res, fell)
	}
}

func TestNativeTimeoutAndStop(t *testing.T) {
	block := func(ctx context.Context, _ []byte) string { <-ctx.Done(); return "" }
	run := WithNative(nil, map[string]NativeHandler{"slow": block})
	p := nativeJob("slow")
	p.TimeoutSeconds = 1
	start := time.Now()
	if res := run(context.Background(), p, t.TempDir()); res.Status != agentproto.RunTimedOut || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout: %+v", res)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	p.TimeoutSeconds = 60
	if res := run(ctx, p, t.TempDir()); res.Status != agentproto.RunFailed {
		t.Fatalf("stop: %+v", res)
	}
}
