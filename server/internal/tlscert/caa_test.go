package tlscert

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// fakeDNS answers CAA queries from a table, by name; a name with no entry has none.
func fakeDNS(t *testing.T, caa map[string][]string, servfail map[string]bool) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		name := strings.TrimSuffix(r.Question[0].Name, ".")
		if servfail[name] {
			m.Rcode = dns.RcodeServerFailure
		}
		for _, v := range caa[name] {
			tag, val, _ := strings.Cut(v, " ")
			m.Answer = append(m.Answer, &dns.CAA{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60}, Tag: tag, Value: strings.Trim(val, `"`)})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestCAAWalksUpTheTree(t *testing.T) {
	le := "https://acme-v02.api.letsencrypt.org/directory"
	for _, c := range []struct {
		name     string
		caa      map[string][]string
		servfail map[string]bool
		http     string
		acct     string
		want     string
	}{
		{"none anywhere", nil, nil, "80", "", CheckOK},
		{"allowed above", map[string][]string{"example.test": {`issue letsencrypt.org`}}, nil, "80", "", CheckOK},
		{"forbidden above", map[string][]string{"example.test": {`issue digicert.com`}}, nil, "80", "", CheckFail},
		{"the nearest set decides", map[string][]string{"rmm.example.test": {`issue letsencrypt.org`}, "example.test": {`issue digicert.com`}}, nil, "80", "", CheckOK},
		{"only iodef", map[string][]string{"example.test": {`iodef mailto:a@b.test`}}, nil, "80", "", CheckOK},
		{"validation methods on offer", map[string][]string{"example.test": {`issue letsencrypt.org;validationmethods=tls-alpn-01`}}, nil, "", "", CheckOK},
		{"validation methods not on offer", map[string][]string{"example.test": {`issue letsencrypt.org;validationmethods=http-01`}}, nil, "", "", CheckFail},
		{"another account", map[string][]string{"example.test": {`issue letsencrypt.org;accounturi=https://acme.test/acct/9`}}, nil, "80", "https://acme.test/acct/1", CheckFail},
		{"this account", map[string][]string{"example.test": {`issue letsencrypt.org;accounturi=https://acme.test/acct/1`}}, nil, "80", "https://acme.test/acct/1", CheckOK},
		{"a failed lookup", nil, map[string]bool{"rmm.example.test": true}, "80", "", CheckWarn},
	} {
		s := New(Deps{}, Settings{Names: []string{"rmm.example.test"}, Directory: le, HTTPPort: c.http, CAAResolvers: []string{fakeDNS(t, c.caa, c.servfail)}})
		s.acctURI = c.acct
		if got := s.caaCheck(context.Background(), "rmm.example.test"); got.Status != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, got.Status, got.Detail, c.want)
		}
	}
	// Another CA: not checked.
	s := New(Deps{}, Settings{Directory: "https://acme.corp.test/dir"})
	if got := s.caaCheck(context.Background(), "x.test"); got.Status != CheckOK || !strings.Contains(got.Detail, "Not checked") {
		t.Errorf("another CA: %+v", got)
	}
}
