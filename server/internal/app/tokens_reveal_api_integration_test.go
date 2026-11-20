//go:build integration

package app_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// TestTokensShownAgainAPI checks that deployment and approval tokens can be
// shown again while active (ADR-0047): the same secret, to those who manage
// them, every time audited; and never for an inactive token or one made
// before secrets were kept.
func TestTokensShownAgainAPI(t *testing.T) {
	h := newHarness(t, false)
	admin, _ := setUp(t, h)
	acme := orgID(t, admin, "Acme")
	var hq idObj
	admin.expect(http.StatusCreated, "POST", "/api/v1/organizations/"+acme+"/sites", map[string]string{"name": "HQ", "timezone": "UTC"}, &hq)
	ctx := context.Background()
	sql := func(q string, args ...any) {
		t.Helper()
		if err := h.db.DB.InTx(ctx, database.System, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, q, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	reveals := func(action, target string) int {
		t.Helper()
		var n int
		if err := h.db.DB.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action = $1 AND target_id = $2 AND actor_type = 'user'`, action, target).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	type token struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
		Kept   bool   `json:"kept"`
	}
	type withSecret struct {
		Token     token  `json:"token"`
		Secret    string `json:"secret"`
		ServerURL string `json:"serverUrl"`
	}

	invite(t, h, admin, "tess@acme.example", []map[string]any{{"role": "technician", "organizationId": acme}})
	tech := h.client()
	tech.signIn("tess@acme.example", "a long and unusual passphrase", "")

	for _, kind := range []struct {
		name, create, base, action string
	}{
		{"deployment", "/api/v1/sites/" + hq.ID + "/enrollment-tokens", "/api/v1/enrollment-tokens/", "enrollment_token.reveal"},
		{"approval", "/api/v1/approval-tokens", "/api/v1/approval-tokens/", "approval_token.reveal"},
	} {
		{
			list := strings.TrimSuffix(kind.base, "/")
			table := "enrollment_tokens"
			if kind.name == "approval" {
				table = "approval_tokens"
			}
			var made, other withSecret
			admin.expect(http.StatusCreated, "POST", kind.create, map[string]any{"name": "Office rollout", "expiresInDays": 7}, &made)
			admin.expect(http.StatusCreated, "POST", kind.create, map[string]any{"name": "Spare", "expiresInDays": 7}, &other)
			if !made.Token.Kept {
				t.Fatalf("%s: a new token is not kept: %+v", kind.name, made.Token)
			}
			var listed struct{ Items []token }

			// Shown again: the same secret, uncached, audited each time.
			var shown withSecret
			r := admin.expect(http.StatusOK, "POST", kind.base+made.Token.ID+"/reveal", nil, &shown)
			if shown.Secret != made.Secret || shown.ServerURL != publicOrigin || shown.Token.ID != made.Token.ID ||
				r.header.Get("Cache-Control") != "no-store" {
				t.Fatalf("%s: shown again = %+v", kind.name, shown)
			}
			admin.expect(http.StatusOK, "POST", kind.base+made.Token.ID+"/reveal", nil, &shown)
			if n := reveals(kind.action, made.Token.ID); n != 2 {
				t.Errorf("%s audit events = %d, want 2", kind.action, n)
			}

			// Not to someone who cannot manage it, nor for a token that is
			// not there.
			if r := tech.do("POST", kind.base+made.Token.ID+"/reveal", nil); r.status != http.StatusNotFound && r.status != http.StatusForbidden {
				t.Errorf("%s: technician showing a token: %d", kind.name, r.status)
			}
			wantStatus(t, admin.do("POST", kind.base+uuid.NewString()+"/reveal", nil), http.StatusNotFound, "not_found")
			wantStatus(t, admin.do("POST", kind.base+"nope/reveal", nil), http.StatusNotFound, "not_found")
			if n := reveals(kind.action, made.Token.ID); n != 2 {
				t.Errorf("%s audit events after refusals = %d, want 2", kind.action, n)
			}

			// A sealed secret copied into another token's row does not open.
			sql(`UPDATE `+table+` SET token_sealed = (SELECT token_sealed FROM `+table+` WHERE id = $1) WHERE id = $2`, made.Token.ID, other.Token.ID)
			wantStatus(t, admin.do("POST", kind.base+other.Token.ID+"/reveal", nil), http.StatusInternalServerError, "")

			// A token made before secrets were kept.
			sql(`UPDATE `+table+` SET token_sealed = NULL WHERE id = $1`, other.Token.ID)
			var got token
			admin.expect(http.StatusOK, "GET", list, nil, &listed)
			for _, x := range listed.Items {
				if x.ID == other.Token.ID {
					got = x
				}
			}
			if got.ID == "" || got.Kept {
				t.Errorf("%s: a token without its secret kept, listed = %+v", kind.name, got)
			}
			wantStatus(t, admin.do("POST", kind.base+other.Token.ID+"/reveal", nil), http.StatusConflict, "token_not_kept")

			// Revoked: nothing to show.
			admin.expect(http.StatusOK, "POST", kind.base+made.Token.ID+"/revoke", nil, nil)
			wantStatus(t, admin.do("POST", kind.base+made.Token.ID+"/reveal", nil), http.StatusConflict, "token_inactive")
			if n := reveals(kind.action, made.Token.ID); n != 2 {
				t.Errorf("%s audit events after an inactive token = %d, want 2", kind.action, n)
			}
		}
	}
}
