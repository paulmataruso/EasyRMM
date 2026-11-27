package updater

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGuard(t *testing.T) {
	dir := t.TempDir()
	g := Guard(dir)
	if err := g(); err != nil {
		t.Fatalf("an empty status directory: %v", err)
	}
	if err := Guard("")(); err != nil {
		t.Fatalf("no directory: %v", err)
	}
	if err := Guard(filepath.Join(dir, "missing"))(); err != nil {
		t.Fatalf("a directory that does not exist: %v", err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(StatusFile, `{"channel":"stable","attempt":{"id":"a","action":"upgrade","result":"succeeded"}}`)
	if err := g(); err != nil {
		t.Fatalf("an ended attempt: %v", err)
	}
	write(StatusFile, `{"attempt":{"result":"running"}}`)
	if err := g(); !errors.Is(err, ErrUpgradeUnderway) {
		t.Fatalf("a running attempt: %v", err)
	}
	write(StatusFile, `not json`)
	if err := g(); !errors.Is(err, ErrUpgradeUnderway) {
		t.Fatalf("an unreadable status: %v", err)
	}
	write(HoldFile, "")
	if err := g(); !errors.Is(err, ErrHeldByUpdater) {
		t.Fatalf("the hold file: %v", err)
	}
}
