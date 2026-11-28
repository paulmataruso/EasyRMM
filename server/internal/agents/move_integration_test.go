//go:build integration

package agents

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

func TestAddressConfirmationIsSignedWithTheDevicesKeyAndRecordedByNonce(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "pc-1")
	auth := agentproto.Auth{Device: d.ID.String(), Nonce: "nonce-address-1"}
	p := &SignedRequest{auth: auth, device: *d}

	ans, err := f.svc.ConfirmAddress(f.ctx, p, "https://rmm.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := agentproto.VerifyAddress(f.k1.Public, ans, d.ID.String(), auth.Nonce, "https://rmm.example.com"); err != nil {
		t.Fatalf("the confirmation does not verify with the ring's key: %v", err)
	}
	// Not another address, another nonce or another device's.
	if agentproto.VerifyAddress(f.k1.Public, ans, d.ID.String(), "other-nonce", "https://rmm.example.com") == nil {
		t.Error("verified against another nonce")
	}
	if agentproto.VerifyAddress(f.k1.Public, ans, d.ID.String(), auth.Nonce, "https://other.example.com") == nil {
		t.Error("verified for another address")
	}
	if n := f.count(`SELECT count(*) FROM issued_instructions WHERE device_id = $1 AND kind = 'address' AND instruction_id = $2`, d.ID, auth.Nonce); n != 1 {
		t.Errorf("recorded %d times", n)
	}

	// With a second key in the ring, a device that trusts only the first is
	// still signed for with the first (ADR-0057).
	k2 := f.secondKey()
	other, _ := f.enroll(f.hq, "pc-2")
	a2 := agentproto.Auth{Device: other.ID.String(), Nonce: "nonce-address-2"}
	ans2, err := f.svc.ConfirmAddress(f.ctx, &SignedRequest{auth: a2, device: *other}, "https://rmm.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if agentproto.VerifyAddress(k2.Public, ans2, other.ID.String(), a2.Nonce, "https://rmm.example.com") != nil &&
		agentproto.VerifyAddress(f.k1.Public, ans2, other.ID.String(), a2.Nonce, "https://rmm.example.com") != nil {
		t.Error("signed by a key that is not the ring's")
	}

	// A retired device is not confirmed to, and neither is a server with no key.
	retired := *d
	retired.Retired = true
	if _, err := f.svc.ConfirmAddress(f.ctx, &SignedRequest{auth: auth, device: retired}, "https://rmm.example.com"); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("retired device: %v", err)
	}
	f.svc.SetUpdates(nil, nil)
	f.svc.SetKeys(nil)
	if _, err := f.svc.ConfirmAddress(f.ctx, p, "https://rmm.example.com"); !errors.Is(err, ErrNoKey) {
		t.Errorf("no key: %v", err)
	}
}

func TestMoveReportsAreAuditedWithBothAddressesAndTheError(t *testing.T) {
	f := newKeyed(t)
	d, _ := f.enroll(f.hq, "pc-1")
	ip := netip.MustParseAddr("192.0.2.77")

	if err := f.svc.Moved(f.ctx, d, ip, agentproto.MoveReport{Kind: agentproto.MoveSetServer, From: "https://203.0.113.10", To: "https://rmm.example.com", Moved: true}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.address_change' AND outcome = 'success' AND target_id = $1
			AND details->>'kind' = 'set-server' AND details->>'from' = 'https://203.0.113.10' AND details->>'to' = 'https://rmm.example.com' AND details->>'device' = 'pc-1'
			AND organization_id = $2 AND site_id = $3`, d.ID.String(), d.OrganizationID, d.SiteID); n != 1 {
		t.Errorf("the change was audited %d times", n)
	}

	if err := f.svc.Moved(f.ctx, d, ip, agentproto.MoveReport{Kind: agentproto.MoveFallback, From: "https://rmm.example.com", To: "https://203.0.113.10",
		Error: "x\n" + strings.Repeat("e", 2*agentproto.MaxMoveError)}); err != nil {
		t.Fatal(err)
	}
	var errText string
	if err := f.db.ReadTx(f.ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(f.ctx, `SELECT details->>'error' FROM audit_log WHERE action = 'device.address_change_failed' AND outcome = 'failure' AND target_id = $1`, d.ID.String()).Scan(&errText)
	}); err != nil {
		t.Fatal(err)
	}
	if len([]rune(errText)) > agentproto.MaxMoveError || strings.ContainsRune(errText, '\n') || !strings.HasPrefix(errText, "x") {
		t.Errorf("the error was stored as %d runes: %q", len([]rune(errText)), errText[:20])
	}

	// Failure without a reason says so.
	if err := f.svc.Moved(f.ctx, d, ip, agentproto.MoveReport{Kind: agentproto.MoveInstall, From: "a", To: "b"}); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'device.address_change_failed' AND details->>'error' = 'The agent did not say why.'`); n != 1 {
		t.Errorf("a report without a reason: %d", n)
	}

	// Reports that are not valid are refused and write nothing.
	before := f.count(`SELECT count(*) FROM audit_log WHERE action LIKE 'device.address_change%'`)
	for name, rep := range map[string]agentproto.MoveReport{
		"unknown kind": {Kind: "move", From: "a", To: "b", Moved: true},
		"no kind":      {From: "a", To: "b"},
		"long from":    {Kind: agentproto.MoveInstall, From: strings.Repeat("a", 301)},
		"long to":      {Kind: agentproto.MoveInstall, To: strings.Repeat("a", 301)},
	} {
		if err := f.svc.Moved(f.ctx, d, ip, rep); !errors.Is(err, ErrBadReport) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if after := f.count(`SELECT count(*) FROM audit_log WHERE action LIKE 'device.address_change%'`); after != before {
		t.Errorf("refused reports wrote %d records", after-before)
	}
}
