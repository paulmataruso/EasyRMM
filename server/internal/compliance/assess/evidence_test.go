package assess

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/google/uuid"
)

func TestEvidenceEncryptionBindsOrganizationAndRow(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	org, ev := uuid.New(), uuid.New()
	plain := []byte("controlled information")
	nonce, ct, err := encrypt(key, evidenceAAD(org, ev), plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 12 || bytes.Contains(ct, plain) {
		t.Fatal("not sealed with a 96-bit nonce")
	}
	got, err := decrypt(key, evidenceAAD(org, ev), nonce, ct)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := decrypt(key, evidenceAAD(uuid.New(), ev), nonce, ct); err == nil {
		t.Error("a blob opened under another organization")
	}
	if _, err := decrypt(key, evidenceAAD(org, uuid.New()), nonce, ct); err == nil {
		t.Error("a blob opened under another row")
	}
	ct[0] ^= 1
	if _, err := decrypt(key, evidenceAAD(org, ev), nonce, ct); err == nil {
		t.Error("a changed blob opened")
	}
	// A fresh nonce each time.
	n2, _, _ := encrypt(key, evidenceAAD(org, ev), plain)
	if bytes.Equal(nonce, n2) {
		t.Error("a nonce was reused")
	}
}

func TestEvidenceInputIsChecked(t *testing.T) {
	for name, in := range map[string]EvidenceInput{
		"no title":      {Title: " ", Body: bytes.NewReader(nil)},
		"no file":       {Title: "x"},
		"ftp link":      {Kind: "link", Title: "x", URL: "ftp://example.test/a"},
		"script link":   {Kind: "link", Title: "x", URL: "javascript:alert(1)"},
		"no host":       {Kind: "link", Title: "x", URL: "https://"},
		"unknown kind":  {Kind: "video", Title: "x", Body: bytes.NewReader(nil)},
		"req no assess": {Title: "x", Body: bytes.NewReader(nil), ReqID: "R"},
	} {
		if err := in.validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	ok := EvidenceInput{Kind: "link", Title: "x", URL: "https://example.test/policy"}
	if err := ok.validate(); err != nil {
		t.Error(err)
	}
}

func TestGeneratedSectionsNeverSayCompliantOrCertified(t *testing.T) {
	r := sampleReport()
	for _, k := range []string{"scope", "requirements", "poam", "score"} {
		s := Generated(k, r)
		if s == "" {
			t.Errorf("%s is empty", k)
		}
		for _, bad := range []string{"compliant", "certified", "Compliant", "Certified"} {
			if bytes.Contains([]byte(s), []byte(bad)) {
				t.Errorf("%s says %q", k, bad)
			}
		}
	}
	if Generated("nothing", r) != "" {
		t.Error("an unknown kind wrote text")
	}
}
