package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/agent/host"
	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Waiting for approval (ADR-0024): an agent installed with an approval
// token asks the server again and again with the same key until someone
// approves or rejects the device in the console. The server holds each
// question open for up to agentproto.ApprovalWait, so an approval arrives
// within a second or two.

// Backoff after errors reaching the server while waiting.
var (
	approvalBackoffMin = 5 * time.Second
	approvalBackoffMax = 5 * time.Minute
)

// awaitApproval waits until the device is approved and returns its
// enrollment. A rejected device stops asking and idles until the service
// stops, rather than exiting and being restarted over and over.
func (e *env) awaitApproval(ctx context.Context) (*state.Config, ed25519.PrivateKey, error) {
	p, key, err := e.store.LoadPending()
	if errors.Is(err, state.ErrNotPending) {
		return nil, nil, state.ErrNotEnrolled
	}
	if err != nil {
		return nil, nil, err
	}
	if p.Stopped != "" {
		return nil, nil, e.idle(ctx, p)
	}
	c, err := client.New(client.Options{Server: p.Server, CAFile: p.CAFile, Version: Version})
	if err != nil {
		return nil, nil, err
	}
	e.log.Info("waiting for approval in the EasyRMM console", "server", p.Server, "code", p.Code)
	var backoff time.Duration
	var lastErr string
	for {
		asked := time.Now()
		resp, err := c.Enroll(ctx, p.Token, key.Public().(ed25519.PublicKey), host.Facts(Version))
		var wait time.Duration
		switch {
		case ctx.Err() != nil:
			return nil, nil, ctx.Err()
		case err == nil && resp.Pending == nil && resp.DeviceID != "":
			cfg := &state.Config{Server: p.Server, CAFile: p.CAFile, DeviceID: resp.DeviceID, EnrolledAt: time.Now().UTC(),
				MeshAgentMode: p.MeshAgentMode}
			cfg.PinFirstKey(resp.JobKey, resp.JobKeyGeneration)
			if err := e.store.Approved(cfg); err != nil {
				return nil, nil, fmt.Errorf("saving the enrollment: %w", err)
			}
			e.log.Info("approved in the EasyRMM console; enrolled", "device_id", resp.DeviceID)
			return cfg, key, nil
		case err == nil && resp.Pending != nil:
			backoff, lastErr = 0, ""
			// The server answered without holding the question open (a
			// restart, or another server): wait before asking again.
			if time.Since(asked) < agentproto.ApprovalWait/2 {
				wait = time.Duration(max(resp.Pending.RetrySeconds, 1)) * time.Second
			}
		case err == nil:
			err = errors.New("the server answered without a device")
			fallthrough
		default:
			if why := stopReason(err); why != "" {
				p.Stopped, p.StoppedAt = why, time.Now().UTC()
				if err := e.store.UpdatePending(p); err != nil {
					e.log.Error("saving the agent's state failed", "error", err)
				}
				return nil, nil, e.idle(ctx, p)
			}
			backoff = min(max(2*backoff, approvalBackoffMin), approvalBackoffMax)
			wait = backoff
			if err.Error() != lastErr {
				lastErr = err.Error()
				e.log.Warn("asking the server about approval failed; trying again", "error", err, "retry_in", backoff)
			}
		}
		if wait > 0 {
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(wait):
			}
		}
	}
}

// stopReason is why the agent should stop asking after err, or "" to keep
// trying: a rejection, or a server that will never accept this request.
func stopReason(err error) string {
	var ce *client.Error
	if !errors.As(err, &ce) {
		return ""
	}
	switch ce.Code {
	case agentproto.CodeEnrollmentRejected:
		return "the device was rejected in the EasyRMM console"
	case "token_invalid":
		return "the install command's token is no longer valid and the server has no request from this device"
	case "key_in_use":
		return "another device is enrolled with this device's key"
	}
	// Anything else (too many requests, a server error) may pass.
	return ""
}

// idle logs why the agent stopped asking and waits for the service to
// stop. Uninstalling and installing again asks anew, with a new key.
func (e *env) idle(ctx context.Context, p *state.Pending) error {
	e.log.Error("the agent stopped asking to enroll: "+p.Stopped+". Uninstall it, then install it again to ask anew.",
		"server", p.Server, "code", p.Code)
	<-ctx.Done()
	return ctx.Err()
}

// pendingStatus prints the state of an agent that is not enrolled.
func (e *env) pendingStatus(ctx context.Context) error {
	p, _, err := e.store.LoadPending()
	if errors.Is(err, state.ErrNotPending) {
		if e.packaged() {
			e.waitingStatus(ctx)
			return nil
		}
		_, _ = fmt.Fprintln(e.stdout, "Not enrolled.")
		return nil
	}
	if err != nil {
		return err
	}
	w := e.stdout
	_, _ = fmt.Fprintf(w, "Server:     %s\nCode:       %s\n", p.Server, p.Code)
	if p.Stopped != "" {
		_, _ = fmt.Fprintf(w, "Stopped:    %s (%s)\n", p.Stopped, p.StoppedAt.Local().Format(time.RFC1123))
	} else {
		_, _ = fmt.Fprintf(w, "Waiting:    for approval in the EasyRMM console since %s\n", p.Since.Local().Format(time.RFC1123))
	}
	if supported() && e.hasServices() {
		_, _ = fmt.Fprintf(w, "Service:    %s\n", e.sd.State(ctx, e.paths.AgentService().Name))
	}
	return nil
}

// waitingStatus prints the state of an agent a package installed without
// input: it waits for the enrollment file (ADR-0056).
func (e *env) waitingStatus(ctx context.Context) {
	w := e.stdout
	_, _ = fmt.Fprintf(w, "Not enrolled.\nWaiting:    for the enrollment file %s; the agent looks for it every %s and enrolls when it appears\n", e.paths.EnrollmentFile(), filePoll)
	e.packageStatus()
	if supported() && e.hasServices() {
		_, _ = fmt.Fprintf(w, "Service:    %s\n", e.sd.State(ctx, e.paths.AgentService().Name))
	}
}

// packageStatus prints the package that holds the agent, and what the agent
// last said of the enrollment file.
func (e *env) packageStatus() {
	rec, err := e.store.LoadPackage()
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(e.stdout, "Package:    %s\n", strings.ToUpper(rec.Kind))
	if rec.Note != "" {
		_, _ = fmt.Fprintf(e.stdout, "File:       %s (%s)\n", rec.Note, rec.NoteAt.Local().Format(time.RFC1123))
	}
}
