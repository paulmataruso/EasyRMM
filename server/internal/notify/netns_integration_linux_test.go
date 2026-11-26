//go:build integration && linux

package notify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// run runs a command, failing the test with its output.
func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// listenIn listens on a TCP address inside a network namespace: a goroutine
// locked to its thread enters the namespace, makes the socket and ends
// without unlocking, so that the thread, which stays in the namespace, is
// thrown away. The socket stays in the namespace, where the host reaches it
// only over the veth pair.
func listenIn(t *testing.T, ns, addr string) net.Listener {
	t.Helper()
	type res struct {
		l   net.Listener
		err error
	}
	ch := make(chan res, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread dies with this goroutine
		f, err := os.Open("/var/run/netns/" + ns)
		if err != nil {
			ch <- res{err: err}
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			ch <- res{err: err}
			return
		}
		l, err := net.Listen("tcp", addr)
		ch <- res{l, err}
	}()
	r := <-ch
	if r.err != nil {
		t.Fatalf("listening in %s: %v", ns, r.err)
	}
	return r.l
}

// selfSigned is a certificate for one IP address, its own authority.
func selfSigned(t *testing.T, ip string) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "receiver"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{net.ParseIP(ip)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// An organization's webhook to a receiver in its own network namespace (a
// private address, across a veth pair) is refused until a super administrator
// approves it, then signed and received, from the address the dial was pinned
// to; withdrawing the approval refuses it again (ADR-0053, slice 3).
func TestAnOrganizationsWebhookInItsOwnNetworkNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("network namespaces need root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip is not installed")
	}
	f := newFx(t)
	var b [2]byte
	_, _ = rand.Read(b[:])
	tag := hex.EncodeToString(b[:])
	ns, host, peer := "n3r"+tag, "n3h"+tag, "n3p"+tag
	// An address range of this test's own.
	oct := strconv.Itoa(100 + int(b[0])%100)
	oct2 := strconv.Itoa(int(b[1]) % 250)
	hostIP, nsIP := fmt.Sprintf("10.%s.%s.1", oct, oct2), fmt.Sprintf("10.%s.%s.2", oct, oct2)
	run(t, "ip", "netns", "add", ns)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", ns).Run()
		_ = exec.Command("ip", "link", "del", host).Run()
	})
	run(t, "ip", "link", "add", host, "type", "veth", "peer", "name", peer)
	run(t, "ip", "link", "set", peer, "netns", ns)
	run(t, "ip", "addr", "add", hostIP+"/24", "dev", host)
	run(t, "ip", "link", "set", host, "up")
	run(t, "ip", "netns", "exec", ns, "ip", "addr", "add", nsIP+"/24", "dev", peer)
	run(t, "ip", "netns", "exec", ns, "ip", "link", "set", peer, "up")
	run(t, "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")

	cert, authority := selfSigned(t, nsIP)
	var seen []string
	var got []recvReq
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		seen = append(seen, r.RemoteAddr)
		got = append(got, recvReq{path: r.URL.RequestURI(), header: r.Header.Clone(), body: buf[:n]})
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Listener.Close()
	srv.Listener = listenIn(t, ns, nsIP+":0")
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	// The environment learns the new interface, as it does every minute.
	f.svc.env.Refresh(f.ctx)

	admin := f.orgAdmin(f.orgA)
	ch, err := f.svc.Create(f.ctx, admin, ChannelInput{OrganizationID: &f.orgA, Kind: KindWebhook, Name: ptr("lan receiver"),
		URL: ptr("https://" + nsIP + ":" + port + "/hook?token=sekrit-query"), TrustedAuthority: ptr(authority)})
	if err != nil {
		t.Fatal(err)
	}
	test := func() TestResult {
		t.Helper()
		f.advance(31 * time.Second)
		res, err := f.svc.Test(f.ctx, admin, ch.ID)
		if err != nil {
			t.Fatal(err)
		}
		// A channel sends one at a time: what was waiting for approval goes first.
		for range 3 {
			f.svc.SendDue(f.ctx)
			if out := f.svc.awaitTest(f.ctx, f.orgA, res.DeliveryID); out.Status != StatusPending || out.Message != "The test is queued and has not been sent yet." {
				return out
			}
		}
		return f.svc.awaitTest(f.ctx, f.orgA, res.DeliveryID)
	}

	// Until approved: refused, nothing reaches the receiver, and a request waits for a super administrator.
	res := test()
	if res.Status != StatusPending || !strings.Contains(res.Message, "Waiting for approval") || len(got) != 0 {
		t.Fatalf("before approval: %+v, %d received", res, len(got))
	}
	reqs, err := f.svc.Requests(f.ctx, f.super())
	if err != nil || len(reqs) != 1 || reqs[0].Host != nsIP || len(reqs[0].Proposed) != 1 || reqs[0].Proposed[0] != nsIP {
		t.Fatalf("requests %+v %v", reqs, err)
	}
	if v, _ := f.svc.Get(f.ctx, admin, ch.ID); v.State != StateWaiting {
		t.Fatalf("state %s", v.State)
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = 'channel_waiting_approval' AND organization_id = $1 AND resolved_at IS NULL`, f.orgA) != 1 {
		t.Fatal("the channel's notice does not say it waits for approval")
	}
	// An approval of another address does not serve it: the prefix must be the receiver's.
	if _, err := f.svc.Approve(f.ctx, f.super(), ch.ID, []string{hostIP + "/32"}); err == nil {
		t.Fatal("approved a prefix that holds no proposed address")
	}

	// Approved: the test goes through, signed, from the host side of the veth pair.
	if _, err := f.svc.Approve(f.ctx, f.super(), ch.ID, []string{nsIP + "/32"}); err != nil {
		t.Fatal(err)
	}
	res = test()
	if res.Status != StatusSent || len(got) == 0 {
		t.Fatalf("after approval: %+v, %d received", res, len(got))
	}
	last := got[len(got)-1]
	if !strings.HasPrefix(seen[len(seen)-1], hostIP+":") {
		t.Fatalf("the receiver saw the connection from %s", seen[len(seen)-1])
	}
	sec, err := f.svc.Reveal(f.ctx, admin, ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	sig := last.header.Get("X-EasyRMM-Signature")
	ts := strings.TrimPrefix(strings.Split(sig, ",")[0], "t=")
	mac := hmac.New(sha256.New, []byte(sec.Secret))
	mac.Write([]byte(ts + "."))
	mac.Write(last.body)
	if want := "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil)); sig != want {
		t.Fatalf("signature %q does not verify (want %q)", sig, want)
	}
	if last.header.Get("X-EasyRMM-Event") != "test" || last.path != "/hook?token=sekrit-query" {
		t.Fatalf("%v %s", last.header, last.path)
	}
	if f.n(`SELECT count(*) FROM notices WHERE kind = 'channel_waiting_approval' AND resolved_at IS NULL`) != 0 {
		t.Fatal("the notice stayed open after the approval")
	}

	// Withdrawn: refused again, at once, on a transport closed with the approval.
	before := len(got)
	if err := f.svc.Withdraw(f.ctx, f.super(), ch.ID); err != nil {
		t.Fatal(err)
	}
	if res = test(); res.Status == StatusSent || len(got) != before {
		t.Fatalf("after withdrawal: %+v, %d received", res, len(got)-before)
	}
	// Changing the host clears an approval: the new destination is a new approval.
	if _, err := f.svc.RequestApproval(f.ctx, admin, ch.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Approve(f.ctx, f.super(), ch.ID, []string{nsIP + "/24"}); err != nil {
		t.Fatal(err)
	}
	if res = test(); res.Status != StatusSent {
		t.Fatalf("approved by network: %+v", res)
	}
	if strings.Contains(f.log.String(), "sekrit-query") {
		t.Fatal("the log holds a URL's query")
	}
}
