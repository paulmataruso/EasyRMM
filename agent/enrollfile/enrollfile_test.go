package enrollfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
	}, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParse(t *testing.T) {
	der := testCert(t)
	ca := base64.StdEncoding.EncodeToString(der)
	f, err := Parse([]byte("\xef\xbb\xbf# made by a package\n\n[enrollment]\r\nserver = https://rmm.example.com \r\nTOKEN=ert_abc\n; a comment\nca=" + ca + "\n"))
	if err != nil || f.Server != "https://rmm.example.com" || f.Token != "ert_abc" || f.CA != ca {
		t.Fatalf("Parse = %+v, %v", f, err)
	}
	if p, err := f.CAPEM(); err != nil || !strings.Contains(string(p), "BEGIN CERTIFICATE") {
		t.Errorf("CAPEM: %v", err)
	}
	// What is written reads back the same.
	if g, err := Parse(f.Marshal()); err != nil || g != f {
		t.Errorf("round trip: %+v, %v", g, err)
	}
	if f, err := Parse([]byte("[enrollment]\n")); err != nil || f != (File{}) {
		t.Errorf("empty section: %+v, %v", f, err)
	}
	for name, body := range map[string]string{
		"another section":   "[other]\nserver=x\n",
		"before the header": "server=x\n[enrollment]\n",
		"unknown key":       "[enrollment]\nserver=x\ntokn=y\n",
		"given twice":       "[enrollment]\ntoken=a\ntoken=b\n",
		"no equals":         "[enrollment]\nserver\n",
		"ca not base64":     "[enrollment]\nca=!!!\n",
		"ca not a cert":     "[enrollment]\nca=" + base64.StdEncoding.EncodeToString([]byte("hello")) + "\n",
		"too large":         "[enrollment]\ntoken=" + strings.Repeat("a", MaxSize) + "\n",
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFromPEM(t *testing.T) {
	der := testCert(t)
	one := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	got, err := FromPEM(one)
	if err != nil || got != base64.StdEncoding.EncodeToString(der) {
		t.Fatalf("FromPEM: %q, %v", got, err)
	}
	if _, err := FromPEM(append(one, one...)); err == nil {
		t.Error("two certificates in one file")
	}
	if _, err := FromPEM([]byte("nothing")); err == nil {
		t.Error("no certificate")
	}
	if _, err := FromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})); err == nil {
		t.Error("a certificate that does not parse")
	}
}

func TestRefusalSaysToRevokeOnlyWhereOthersCouldRead(t *testing.T) {
	r := &Refusal{Path: "/etc/x/install.conf", Reason: "has mode 0644", Readable: true}
	if !strings.Contains(r.Error(), "revoke the token") {
		t.Error(r.Error())
	}
	if strings.Contains((&Refusal{Path: "p", Reason: "is a symbolic link"}).Error(), "revoke") {
		t.Error("revoke said for a file others could not read")
	}
	var target *Refusal
	if !errors.As(error(r), &target) {
		t.Error("not an error of its type")
	}
}
