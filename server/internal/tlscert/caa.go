package tlscert

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CAA (RFC 8659) is read up the tree from the name: the first name with a
// record set decides. The check understands Let's Encrypt's identity,
// letsencrypt.org, with its accounturi and validationmethods parameters; for
// another CA it says it did not check.
func (s *Service) caaCheck(ctx context.Context, name string) Check {
	c := Check{ID: "caa", Title: "CAA allows Let's Encrypt"}
	if !strings.Contains(strings.ToLower(hostOfURL(s.set.Directory)), "letsencrypt.org") {
		c.Status, c.Detail = CheckOK, "Not checked: the CA is not Let's Encrypt."
		return c
	}
	recs, at, err := s.lookupCAA(ctx, name)
	if err != nil {
		c.Status = CheckWarn
		c.Detail = "The CAA records could not be read: " + err.Error() + "."
		c.Fix = "Let's Encrypt fails an order when it cannot read CAA. A DNSSEC failure is the usual cause: check the zone's signatures first."
		return c
	}
	if len(recs) == 0 {
		c.Status, c.Detail = CheckOK, "No CAA record restricts issuance."
		return c
	}
	var issue []string
	for _, r := range recs {
		if strings.EqualFold(r.Tag, "issue") {
			issue = append(issue, r.Value)
		}
	}
	if len(issue) == 0 {
		c.Status, c.Detail = CheckOK, "The CAA records at "+at+" do not restrict who may issue."
		return c
	}
	for _, v := range issue {
		parts := strings.Split(v, ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "letsencrypt.org") {
			continue
		}
		okMethod, okAccount := true, true
		for _, p := range parts[1:] {
			k, val, _ := strings.Cut(strings.TrimSpace(p), "=")
			switch strings.ToLower(k) {
			case "validationmethods":
				okMethod = false
				for _, m := range strings.Split(val, ",") {
					m = strings.TrimSpace(m)
					if m == "tls-alpn-01" || (m == "http-01" && s.set.HTTPPort != "") {
						okMethod = true
					}
				}
			case "accounturi":
				if uri := s.accountURI(); uri != "" && val != uri {
					okAccount = false
				}
			}
		}
		switch {
		case !okMethod:
			c.Status, c.Detail = CheckFail, "The CAA record at "+at+" names validation methods this server does not offer."
			c.Fix = "Add http-01 or tls-alpn-01 to validationmethods."
		case !okAccount:
			c.Status, c.Detail = CheckFail, "The CAA record at "+at+" names another ACME account than this server's."
			c.Fix = "Set accounturi to this server's account: " + s.accountURI()
		default:
			c.Status, c.Detail = CheckOK, "The CAA record at "+at+" allows letsencrypt.org."
		}
		return c
	}
	c.Status, c.Detail = CheckFail, "The CAA records at "+at+" do not allow letsencrypt.org."
	c.Fix = `Add a CAA record: 0 issue "letsencrypt.org".`
	return c
}

func hostOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

type caaRecord struct{ Tag, Value string }

// lookupCAA walks up from the name and returns the first CAA set found, and
// the name it was found at.
func (s *Service) lookupCAA(ctx context.Context, name string) ([]caaRecord, string, error) {
	servers := s.set.CAAResolvers
	if len(servers) == 0 {
		cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(cc.Servers) == 0 {
			return nil, "", fmt.Errorf("no resolver to ask")
		}
		for _, sv := range cc.Servers {
			servers = append(servers, net.JoinHostPort(sv, cc.Port))
		}
	}
	labels := dns.SplitDomainName(name)
	for i := range labels {
		n := dns.Fqdn(strings.Join(labels[i:], "."))
		var resp *dns.Msg
		var lastErr error
		for _, sv := range servers {
			m := new(dns.Msg)
			m.SetQuestion(n, dns.TypeCAA)
			m.RecursionDesired = true
			cl := &dns.Client{Timeout: 5 * time.Second}
			r, _, err := cl.ExchangeContext(ctx, m, sv)
			if err != nil {
				lastErr = err
				continue
			}
			if r.Rcode == dns.RcodeServerFailure {
				lastErr = fmt.Errorf("the resolver answered SERVFAIL for %s", strings.TrimSuffix(n, "."))
				continue
			}
			resp, lastErr = r, nil
			break
		}
		if resp == nil {
			return nil, "", lastErr
		}
		var recs []caaRecord
		for _, rr := range resp.Answer {
			if c, ok := rr.(*dns.CAA); ok {
				recs = append(recs, caaRecord{Tag: c.Tag, Value: c.Value})
			}
		}
		if len(recs) > 0 {
			return recs, strings.TrimSuffix(n, "."), nil
		}
	}
	return nil, "", nil
}
