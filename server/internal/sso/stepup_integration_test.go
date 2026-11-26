//go:build integration

package sso_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/sso"
	"github.com/paulmataruso/easyrmm/server/internal/sso/ssotest"
)

// session signs email in through the provider and returns its session.
func (e *env) session(providerID uuid.UUID, email string) *auth.Session {
	e.t.Helper()
	res, err := e.signIn(providerID, email, "")
	if err != nil {
		e.t.Fatal(err)
	}
	s, _, err := e.auth.Authenticate(context.Background(), res.Token)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func TestStepUpThroughDex(t *testing.T) {
	e := newEnv(t)
	e.auth.SetClock(func() time.Time { return *e.now })
	ctx := context.Background()
	e.user(ssotest.Alex)
	e.user(ssotest.Sam)
	p := e.provider(func(in *sso.ProviderInput) { in.TrustMFA = true })
	sess := e.session(p.ID, ssotest.Alex)
	if sess.State != auth.StateActive || sess.SSOProviderID == nil || *sess.SSOProviderID != p.ID || sess.SteppedUpAt != nil {
		t.Fatalf("session = %+v", sess)
	}
	user := &auth.User{ID: sess.UserID}

	st, err := e.auth.StepUpStatus(ctx, sess, user)
	if err != nil || len(st.Methods) != 1 || st.Methods[0] != auth.StepUpOIDC || st.Provider != "Dex" {
		t.Fatalf("status = %+v %v", st, err)
	}

	start := func(s *auth.Session) (string, url.Values) {
		e.t.Helper()
		authURL, err := e.svc.StartStepUp(ctx, s, "/devices?x=1", e.meta)
		if err != nil {
			e.t.Fatalf("start: %v", err)
		}
		u, _ := url.Parse(authURL)
		return authURL, u.Query()
	}
	finish := func(authURL, email string) (string, error) {
		e.t.Helper()
		q := e.dex.SignIn(e.t, authURL, email).Query()
		return e.svc.CompleteStepUp(ctx, sso.CallbackInput{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error")}, e.meta)
	}

	e.run("asks for a fresh sign-in, bound to the session", func(e *env) {
		t := e.t
		authURL, q := start(sess)
		if q.Get("prompt") != "login" || q.Get("max_age") != "0" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" {
			t.Fatalf("authorization URL = %s", authURL)
		}
		if !e.svc.IsStepUp(ctx, q.Get("state")) || e.svc.IsStepUp(ctx, "another-state") {
			t.Fatal("IsStepUp does not tell the step-up's state from another")
		}
	})

	e.run("the linked identity's fresh sign-in steps the session up", func(e *env) {
		t := e.t
		authURL, _ := start(sess)
		back, err := finish(authURL, ssotest.Alex)
		if err != nil {
			t.Fatalf("complete: %v", err)
		}
		if back != "/devices?x=1" {
			t.Fatalf("return = %q", back)
		}
		if n := e.count(`SELECT count(*) FROM sessions WHERE id = $1 AND stepped_up_at IS NOT NULL AND step_up_state_hash IS NULL AND step_up_nonce IS NULL`, sess.ID); n != 1 {
			t.Fatalf("stepped up rows = %d", n)
		}
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'auth.step_up' AND outcome = 'success' AND details->>'method' = 'oidc'`); n != 1 {
			t.Fatalf("success audits = %d", n)
		}
	})

	e.run("the answer is used once", func(e *env) {
		t := e.t
		authURL, _ := start(sess)
		q := e.dex.SignIn(t, authURL, ssotest.Alex).Query()
		in := sso.CallbackInput{State: q.Get("state"), Code: q.Get("code")}
		if _, err := e.svc.CompleteStepUp(ctx, in, e.meta); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.CompleteStepUp(ctx, in, e.meta); failureCode(err) != sso.FailExpired {
			t.Fatalf("replay: %v", err)
		}
		if e.svc.IsStepUp(ctx, in.State) {
			t.Fatal("a used step-up is still pending")
		}
	})

	e.run("another account at the same provider does not pass", func(e *env) {
		t := e.t
		before := e.count(`SELECT count(*) FROM audit_log WHERE action = 'auth.step_up' AND outcome = 'failure'`)
		authURL, _ := start(sess)
		if _, err := finish(authURL, ssotest.Sam); failureCode(err) != sso.FailStepUpIdentity {
			t.Fatalf("another identity: %v", err)
		}
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'auth.step_up' AND outcome = 'failure' AND details->>'reason' = 'identity'`); n != before+1 {
			t.Fatalf("failure audits = %d", n)
		}
		if n := e.count(`SELECT reauth_failures FROM sessions WHERE id = $1`, sess.ID); n < 1 {
			t.Fatalf("failures counted = %d", n)
		}
	})

	e.run("a provider no longer trusted to enforce MFA does not pass", func(e *env) {
		t := e.t
		authURL, _ := start(sess)
		e.exec(`UPDATE identity_providers SET trust_mfa = false WHERE id = $1`, p.ID)
		defer e.exec(`UPDATE identity_providers SET trust_mfa = true WHERE id = $1`, p.ID)
		if _, err := finish(authURL, ssotest.Alex); failureCode(err) != sso.FailStepUpTrust {
			t.Fatalf("untrusted: %v", err)
		}
		if _, err := e.svc.StartStepUp(ctx, sess, "", e.meta); !errors.Is(err, auth.ErrNoSecondFactor) {
			t.Fatalf("start with an untrusted provider: %v", err)
		}
	})

	e.run("a sign-in that is not after the start does not pass", func(e *env) {
		t := e.t
		authURL, _ := start(sess)
		// The provider's answer carries an auth_time from before the step-up
		// started: here, the start is moved ahead of it.
		e.exec(`UPDATE sessions SET step_up_started_at = step_up_started_at + interval '2 minutes' WHERE id = $1`, sess.ID)
		if _, err := finish(authURL, ssotest.Alex); failureCode(err) != sso.FailStepUpAuthTime {
			t.Fatalf("stale auth_time: %v", err)
		}
	})

	e.run("a step-up that took too long is gone", func(e *env) {
		t := e.t
		authURL, _ := start(sess)
		*e.now = e.now.Add(auth.StepUpFlowTTL + time.Minute)
		if _, err := finish(authURL, ssotest.Alex); failureCode(err) != sso.FailExpired {
			t.Fatalf("late: %v", err)
		}
	})
}
