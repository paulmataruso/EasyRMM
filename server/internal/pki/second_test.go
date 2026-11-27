package pki

import (
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestSecondCertificateCoversAddedNamesOnly(t *testing.T) {
	now := time.Now()
	a := newAuthority(t, now)
	if err := a.SetAddresses(context.Background(), nil, []net.IP{net.ParseIP("203.0.113.10")}); err != nil {
		t.Fatal(err)
	}
	main, err := a.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := a.SecondCertificate([]string{"Rmm.Example.com", "mesh.rmm.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Leaf.DNSNames; len(got) != 2 || got[0] != "rmm.example.com" || len(second.Leaf.IPAddresses) != 0 {
		t.Fatalf("names %v ips %v", got, second.Leaf.IPAddresses)
	}
	// The server certificate every agent sees on the IP is untouched, and the
	// second one shares its key, so a key pin held for the server holds.
	again, _ := a.Certificate()
	if again.Leaf.SerialNumber.Cmp(main.Leaf.SerialNumber) != 0 || len(again.Leaf.DNSNames) != 0 {
		t.Error("the server certificate changed")
	}
	if second.PrivateKey != main.PrivateKey {
		t.Error("the second certificate must use the server key")
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.ca)
	if _, err := second.Leaf.Verify(x509.VerifyOptions{DNSName: "mesh.rmm.example.com", Roots: pool, CurrentTime: now}); err != nil {
		t.Fatalf("does not verify against the authority: %v", err)
	}
	same, _ := a.SecondCertificate([]string{"rmm.example.com", "mesh.rmm.example.com"})
	if same != second {
		t.Error("not reused")
	}
	if _, err := a.SecondCertificate(nil); err == nil {
		t.Error("no names must be refused")
	}
}
