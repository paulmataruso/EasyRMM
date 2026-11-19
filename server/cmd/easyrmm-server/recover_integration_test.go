//go:build integration

package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestRecoverCommand(t *testing.T) {
	setEnv(t)
	var out, errs bytes.Buffer
	run := func(args ...string) int {
		out.Reset()
		errs.Reset()
		return recoverCommand(args, &out, &errs)
	}

	// Before anyone exists (and on a database not yet migrated).
	if got := run(); got != 1 || !strings.Contains(errs.String(), "there is no active super administrator") {
		t.Fatalf("no administrator: %d %q", got, errs.String())
	}

	conn, err := pgx.Connect(context.Background(), os.Getenv("EASYRMM_DATABASE_MIGRATION_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), `WITH u AS (INSERT INTO users (email, display_name) VALUES ('admin@example.com', 'Admin') RETURNING id)
		INSERT INTO role_assignments (user_id, role) SELECT id, 'super_admin' FROM u`); err != nil {
		t.Fatal(err)
	}
	if got := run(); got != 0 || !strings.Contains(out.String(), "https://rmm.test/recover#token=") {
		t.Fatalf("recover: %d %q %q", got, out.String(), errs.String())
	}
	if got := run("--email", "admin@example.com"); got != 0 {
		t.Fatalf("recover --email: %d %q", got, errs.String())
	}
	if got := run("--email", "nobody@example.com"); got != 1 || !strings.Contains(errs.String(), "nobody@example.com is not an active super administrator") {
		t.Fatalf("someone else: %d %q", got, errs.String())
	}
}

func TestRecoverCommandArguments(t *testing.T) {
	var out, errs bytes.Buffer
	if got := recoverCommand([]string{"--bogus"}, &out, &errs); got != 2 {
		t.Errorf("unknown flag = %d", got)
	}
	if got := recoverCommand([]string{"extra"}, &out, &errs); got != 2 || !strings.Contains(errs.String(), `unexpected argument "extra"`) {
		t.Errorf("extra argument = %d %q", got, errs.String())
	}
	if got := recoverCommand([]string{"-h"}, &out, &errs); got != 0 {
		t.Errorf("help = %d", got)
	}
	t.Setenv("EASYRMM_PUBLIC_URL", "")
	t.Setenv("EASYRMM_SECRET_KEY", "")
	if got := recoverCommand(nil, &out, &errs); got != 1 || !strings.Contains(errs.String(), "configuration error") {
		t.Errorf("invalid configuration = %d %q", got, errs.String())
	}
	// Through run, as the image's users call it.
	if got := run([]string{"recover", "--bogus"}); got != 2 {
		t.Errorf("run recover --bogus = %d", got)
	}
}
