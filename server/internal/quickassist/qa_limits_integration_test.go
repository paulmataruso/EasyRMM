//go:build integration

package quickassist_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/quickassist"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// active makes an accepted session and returns its id and device.
func (f *fx) active(holder access.Caller) (uuid.UUID, uuid.UUID) {
	f.t.Helper()
	l := f.oneTime(holder, f.acme)
	r, err := f.runner(l.Token, "123456")
	if err != nil {
		f.t.Fatal(err)
	}
	sid := uuid.MustParse(r.SessionID)
	if _, err := f.svc.Accept(f.ctx, holder, sid, "123456"); err != nil {
		f.t.Fatal(err)
	}
	return sid, uuid.MustParse(r.DeviceID)
}

func TestSettingsLoadUpdateAndBounds(t *testing.T) {
	f := newFx(t)
	got, err := f.svc.LoadSettings(f.ctx)
	if err != nil || got != quickassist.DefaultSettings() {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	// An unusable stored value is the default, not an error.
	f.exec(`INSERT INTO settings (key, value) VALUES ('quickassist.idle_minutes', '3'), ('quickassist.waiting_cap', '"many"'), ('quickassist.bucket_burst', '7')`)
	got, _ = f.svc.LoadSettings(f.ctx)
	if got.IdleMinutes != 30 || got.WaitingCap != 20 || got.BucketBurst != 7 {
		t.Fatalf("stored: %+v", got)
	}
	admin := f.user(rbac.RoleOrgAdmin, f.acme)
	ten, bad := 10, 366
	if _, err := f.svc.UpdateSettings(f.ctx, admin, quickassist.SettingsPatch{IdleMinutes: &ten}); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("org admin: %v", err)
	}
	sys := access.System("test")
	if _, err := f.svc.UpdateSettings(f.ctx, sys, quickassist.SettingsPatch{IdleMinutes: &ten, RetentionDays: &bad}); err == nil {
		t.Fatal("out-of-range accepted")
	}
	if got, _ = f.svc.LoadSettings(f.ctx); got.IdleMinutes != 30 {
		t.Fatalf("a refused change wrote something: %+v", got)
	}
	if got, err = f.svc.UpdateSettings(f.ctx, sys, quickassist.SettingsPatch{IdleMinutes: &ten}); err != nil || got.IdleMinutes != 10 || got.BucketBurst != 7 {
		t.Fatalf("update: %+v %v", got, err)
	}
	if a := f.actions("quickassist.settings.update"); len(a) != 1 {
		t.Fatalf("audit: %v", a)
	}
}

func TestIdleSweepEndsQuietSessionAndActivityKeepsItAlive(t *testing.T) {
	f := newFx(t)
	tech := f.user(rbac.RoleTechnician, f.acme)
	quiet, quietDev := f.active(tech)
	busy, busyDev := f.active(tech)
	f.exec(`UPDATE quick_assist_sessions SET last_activity_at = now() - interval '31 minutes'`)
	if err := f.svc.TouchSession(f.ctx, busyDev); err != nil {
		t.Fatal(err)
	}
	// The runner is told by its poll before the sweep even runs.
	if st, _ := f.svc.Status(f.ctx, quietDev); st.State != quickassist.SessionEnded || st.EndReason != "idle" {
		t.Fatalf("status: %+v", st)
	}
	f.exec(`UPDATE quick_assist_sessions SET state = 'active', end_reason = '', ended_at = NULL WHERE id = $1`, quiet)
	if err := f.svc.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND state = 'ended' AND end_reason = 'idle'`, quiet); n != 1 {
		t.Fatal("the quiet session was not ended")
	}
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND state = 'active'`, busy); n != 1 {
		t.Fatal("the touched session was ended")
	}
	if a := f.actions("quickassist.session.end"); len(a) != 1 {
		t.Fatalf("audit: %v", a)
	}
	// The limit is a setting.
	f.exec(`INSERT INTO settings (key, value) VALUES ('quickassist.idle_minutes', '240')`)
	f.exec(`UPDATE quick_assist_sessions SET last_activity_at = now() - interval '3 hours' WHERE id = $1`, busy)
	if err := f.svc.Sweep(f.ctx); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM quick_assist_sessions WHERE id = $1 AND state = 'active'`, busy); n != 1 {
		t.Fatal("a 4 hour limit ended a session idle for 3")
	}
}

func TestExtendSessionOnceByTheHolderOnly(t *testing.T) {
	f := newFx(t)
	tech := f.user(rbac.RoleTechnician, f.acme)
	other := f.user(rbac.RoleTechnician, f.acme)
	admin := f.user(rbac.RoleOrgAdmin, f.acme)
	sid, _ := f.active(tech)
	var before time.Time
	f.scanTime(`SELECT expires_at FROM quick_assist_sessions WHERE id = $1`, &before, sid)

	if _, err := f.svc.ExtendSession(f.ctx, other, sid); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("another technician extended: %v", err)
	}
	x, err := f.svc.ExtendSession(f.ctx, tech, sid)
	if err != nil || !x.Extended || x.ExpiresAt.Sub(before) != quickassist.MaxSessionLife {
		t.Fatalf("extend: %+v %v", x, err)
	}
	if _, err := f.svc.ExtendSession(f.ctx, tech, sid); !conflict(err) {
		t.Fatalf("second extension: %v", err)
	}
	if _, err := f.svc.ExtendSession(f.ctx, admin, sid); !conflict(err) {
		t.Fatalf("second extension by a taker-over: %v", err)
	}
	if a := f.actions("quickassist.session.extend"); len(a) != 1 {
		t.Fatalf("audit: %v", a)
	}
	// A session that is not running cannot be extended.
	if err := f.svc.End(f.ctx, tech, sid); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ExtendSession(f.ctx, tech, sid); !conflict(err) {
		t.Fatalf("extending an ended session: %v", err)
	}
	// Someone who may take sessions over can extend one they do not hold.
	sid2, _ := f.active(tech)
	if _, err := f.svc.ExtendSession(f.ctx, admin, sid2); err != nil {
		t.Fatalf("takeover permission: %v", err)
	}
}

func TestStaleLinksAreMarkedThenRevoked(t *testing.T) {
	f := newFx(t)
	f.openMode()
	admin := f.user(rbac.RoleOrgAdmin, f.acme)
	mk := func(name string) *quickassist.NewLink {
		l, err := f.svc.CreateLink(f.ctx, admin, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	fresh, aging, dead := mk("fresh"), mk("aging"), mk("dead")
	oneTime := f.oneTime(admin, f.acme)
	f.exec(`UPDATE quick_assist_links SET last_used_at = now() - interval '91 days' WHERE id = $1`, aging.Link.ID)
	f.exec(`UPDATE quick_assist_links SET created_at = now() - interval '181 days' WHERE id = $1`, dead.Link.ID)
	f.exec(`UPDATE quick_assist_links SET last_used_at = now() - interval '200 days' WHERE id = $1`, oneTime.Link.ID)
	if err := f.svc.SweepLinks(f.ctx); err != nil {
		t.Fatal(err)
	}
	state := func(id uuid.UUID) (string, bool) {
		links, err := f.svc.ListLinks(f.ctx, admin, f.acme)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range links {
			if l.ID == id {
				return l.State, l.Stale
			}
		}
		t.Fatal("link missing")
		return "", false
	}
	if s, st := state(fresh.Link.ID); s != "active" || st {
		t.Fatalf("fresh: %s %v", s, st)
	}
	if s, st := state(aging.Link.ID); s != "active" || !st {
		t.Fatalf("aging: %s %v", s, st)
	}
	if s, _ := state(dead.Link.ID); s != "revoked" {
		t.Fatalf("dead: %s", s)
	}
	if s, st := state(oneTime.Link.ID); s != "active" || st {
		t.Fatalf("a one-time link was swept: %s %v", s, st)
	}
	if a := f.actions("quickassist.link.revoked"); len(a) != 1 {
		t.Fatalf("audit: %v", a)
	}
	// Using a stale link clears the mark.
	if _, _, err := f.svc.Download(f.ctx, f.ip(), aging.Token); err != nil {
		t.Fatal(err)
	}
	if _, st := state(aging.Link.ID); st {
		t.Fatal("use did not clear the stale mark")
	}
}

func TestSettingsChangeBucketAndCaps(t *testing.T) {
	f := newFx(t)
	f.openMode()
	admin := f.user(rbac.RoleOrgAdmin, f.acme)
	f.exec(`INSERT INTO settings (key, value) VALUES ('quickassist.permanent_link_cap', '1')`)
	l, err := f.svc.CreateLink(f.ctx, admin, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateLink(f.ctx, admin, quickassist.CreateInput{OrganizationID: f.acme, Kind: quickassist.KindPermanent}); !conflict(err) {
		t.Fatalf("cap of 1: %v", err)
	}
	f.exec(`INSERT INTO settings (key, value) VALUES ('quickassist.bucket_burst', '1'), ('quickassist.bucket_refill_minutes', '60')`)
	f.exec(`UPDATE quick_assist_links SET bucket_tokens = 5 WHERE id = $1`, l.Link.ID)
	if _, _, err := f.svc.Download(f.ctx, f.ip(), l.Token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.svc.Download(f.ctx, f.ip(), l.Token); !errors.Is(err, quickassist.ErrThrottled) {
		t.Fatalf("burst of 1: %v", err)
	}
}
