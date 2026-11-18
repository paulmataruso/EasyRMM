package auditfwd

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

func dialT(t *testing.T, d Destination) *conn {
	t.Helper()
	c, err := dial(context.Background(), d)
	if err != nil {
		t.Fatalf("dial: %v (%s)", err, describe(d, err))
	}
	t.Cleanup(c.close)
	return c
}

func TestTCPSendsFramesInOrder(t *testing.T) {
	col := newCollector(t, TCP, nil)
	c := dialT(t, Destination{Transport: TCP, Host: "127.0.0.1", Port: col.port})
	msgs := [][]byte{[]byte("<110>1 one"), []byte("<110>1 two\nlines"), []byte("<110>1 " + strings.Repeat("é", 3000))}
	if err := c.send(msgs); err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		if got := col.next(t); got != string(m) {
			t.Fatalf("received %q, want %q", got[:min(len(got), 40)], m[:min(len(m), 40)])
		}
	}
	if !c.alive() {
		t.Fatal("idle connection reported closed")
	}
	// A collector that restarts closes the connection; the next round must
	// notice before it sends.
	col.drop()
	deadline := time.Now().Add(5 * time.Second)
	for c.alive() {
		if time.Now().After(deadline) {
			t.Fatal("closed connection still reported open")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestTLS(t *testing.T) {
	pki := newPKI(t)
	col := newCollector(t, TLS, pki.serverTLS(t, false))
	d := Destination{Transport: TLS, Host: "127.0.0.1", Port: col.port, CACert: pki.caPEM}
	c := dialT(t, d)
	if err := c.send([][]byte{[]byte("<110>1 over tls")}); err != nil {
		t.Fatal(err)
	}
	if got := col.next(t); got != "<110>1 over tls" {
		t.Fatalf("received %q", got)
	}

	// Without the authority's certificate the system's do not trust it.
	d.CACert = ""
	_, err := dial(context.Background(), d)
	if msg := describe(d, err); !strings.Contains(msg, "not signed by a trusted certificate authority") {
		t.Errorf("unknown authority: %v (%s)", err, msg)
	}
	// A certificate for another name is refused.
	other := newCollector(t, TLS, func() *tls.Config {
		_, _, pair := pki.issue(t, []string{"collector.test"}, nil, false)
		return &tls.Config{Certificates: []tls.Certificate{pair}}
	}())
	d = Destination{Transport: TLS, Host: "127.0.0.1", Port: other.port, CACert: pki.caPEM}
	_, err = dial(context.Background(), d)
	if msg := describe(d, err); !strings.Contains(msg, "not valid for 127.0.0.1") {
		t.Errorf("wrong name: %v (%s)", err, msg)
	}
	// A plain-TCP collector does not speak TLS.
	plain := newCollector(t, TCP, nil)
	d = Destination{Transport: TLS, Host: "127.0.0.1", Port: plain.port, CACert: pki.caPEM}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := dial(ctx, d); err == nil {
		t.Error("TLS to a plain collector succeeded")
	}
}

func TestMutualTLS(t *testing.T) {
	pki := newPKI(t)
	col := newCollector(t, TLS, pki.serverTLS(t, true))
	d := Destination{Transport: TLS, Host: "127.0.0.1", Port: col.port, CACert: pki.caPEM}
	// TLS 1.3 refuses the missing certificate after the client's handshake
	// has finished; the connection must still fail before anything is sent.
	_, err := dial(context.Background(), d)
	if err == nil {
		t.Fatal("connected without the required client certificate")
	}
	if msg := describe(d, err); !strings.Contains(msg, "client certificate") {
		t.Errorf("missing client certificate: %v (%s)", err, msg)
	}
	cert, key, _ := pki.issue(t, nil, nil, true)
	d.ClientCert, d.ClientKey = cert, []byte(key)
	c := dialT(t, d)
	if err := c.send([][]byte{[]byte("<110>1 mutual")}); err != nil {
		t.Fatal(err)
	}
	if got := col.next(t); got != "<110>1 mutual" {
		t.Fatalf("received %q", got)
	}
	d.ClientKey = []byte("not a key")
	if _, err := dial(context.Background(), d); err == nil || !strings.Contains(err.Error(), "do not form a pair") {
		t.Errorf("bad key: %v", err)
	}
	d.CACert = "not a certificate"
	if _, err := dial(context.Background(), d); err == nil || !strings.Contains(err.Error(), "not a PEM certificate") {
		t.Errorf("bad CA: %v", err)
	}
}

func TestUDP(t *testing.T) {
	col := newCollector(t, UDP, nil)
	c := dialT(t, Destination{Transport: UDP, Host: "127.0.0.1", Port: col.port})
	if err := c.send([][]byte{[]byte("<110>1 a"), []byte("<110>1 b")}); err != nil {
		t.Fatal(err)
	}
	if a, b := col.next(t), col.next(t); a != "<110>1 a" || b != "<110>1 b" {
		t.Fatalf("received %q %q", a, b)
	}
	if !c.alive() || c.refused(50*time.Millisecond) || c.limit != maxDatagram {
		t.Fatal("UDP connection state")
	}
	// Nothing listening: loopback answers with port unreachable.
	d := Destination{Transport: UDP, Host: "127.0.0.1", Port: closedPort(t, "udp")}
	c = dialT(t, d)
	_ = c.send([][]byte{[]byte("<110>1 lost")})
	if !c.refused(time.Second) {
		t.Fatal("refusal not noticed")
	}
}

func TestDialFailures(t *testing.T) {
	d := Destination{Transport: TCP, Host: "127.0.0.1", Port: closedPort(t, "tcp")}
	_, err := dial(context.Background(), d)
	if msg := describe(d, err); !strings.Contains(msg, "Connection refused: nothing accepts TCP connections on 127.0.0.1:") {
		t.Errorf("refused: %s", msg)
	}
	col := newCollector(t, TCP, nil)
	col.closeOnAccept.Store(true)
	d.Port = col.port
	_, err = dial(context.Background(), d)
	if msg := describe(d, err); !strings.Contains(msg, "closed the connection as soon as it was opened") {
		t.Errorf("closed at once: %v (%s)", err, msg)
	}
	if _, err := dial(context.Background(), Destination{Transport: "sctp"}); err == nil {
		t.Error("unknown transport accepted")
	}
	// Not to cloud instance metadata, over any transport (netguard).
	for _, tr := range []string{TCP, UDP, TLS} {
		md := Destination{Transport: tr, Host: "169.254.169.254", Port: 514}
		_, err := dial(context.Background(), md)
		if msg := describe(md, err); !strings.Contains(msg, "does not connect to 169.254.169.254") {
			t.Errorf("%s to a metadata address: %v (%s)", tr, err, msg)
		}
	}
	for _, c := range []struct {
		err  error
		want string
	}{
		{&net.DNSError{Err: "no such host", Name: "siem.invalid", IsNotFound: true}, "could not be resolved"},
		{&net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}, "Timed out reaching"},
		{errTest, "test"},
		{errorString(strings.Repeat("x", 600)), strings.Repeat("x", 500)},
	} {
		if got := describe(Destination{Transport: TCP, Host: "siem.invalid", Port: 514}, c.err); !strings.Contains(got, c.want) || len(got) > 500 {
			t.Errorf("describe(%v) = %q", c.err, got)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type errorString string

func (e errorString) Error() string { return string(e) }
