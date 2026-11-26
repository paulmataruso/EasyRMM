package trust

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Store is where the agent keeps what the instruction changes (state.Store).
type Store interface {
	SaveConfig(*state.Config) error
	SaveCA(pem []byte) (string, error)
	LoadTrustLog() state.TrustLog
	SaveTrustLog(state.TrustLog) error
}

// Retruster makes the running client trust what was widened (client.Client).
type Retruster interface {
	Retrust(caFile string, trustSystem bool) error
}

// keepHandled is how many handled instructions the agent remembers.
const keepHandled = 8

// Agent handles the trust instructions of heartbeat answers.
type Agent struct {
	// DeviceID is this device's; an instruction for another is refused.
	DeviceID string
	// Config is the enrollment, whose CAFile and TrustSystem a widening
	// changes. Its Server names the origin instructions must be for.
	Config *state.Config
	// Key returns the pinned job-signing key, nil while none is pinned: an
	// agent that has pinned none refuses every instruction. Trust is never
	// widened on first use.
	Key      func() ed25519.PublicKey
	Store    Store
	Client   Retruster
	Verifier Verifier
	Log      *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu     sync.Mutex
	report *agentproto.TrustReport
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Caps is what the agent announces in its heartbeat.
func (a *Agent) Caps() []string { return []string{agentproto.CapTrust} }

// Report is the report to send with the next heartbeat, nil when there is
// none.
func (a *Agent) Report() *agentproto.TrustReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.report
}

func (a *Agent) setReport(r *agentproto.TrustReport) {
	a.mu.Lock()
	a.report = r
	a.mu.Unlock()
}

// origin is the host the agent's signed requests go to.
func (a *Agent) origin() string {
	u, err := url.Parse(a.Config.Server)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// trusts says what the agent trusts now, for its report.
func (a *Agent) trusts() string {
	switch {
	case a.Config.CAFile == "":
		return "system"
	case a.Config.TrustSystem:
		return "system+ca-file"
	default:
		return "ca-file"
	}
}

// Answered handles a heartbeat answer's trust instruction, nil when it
// carried none: then the report of an earlier one, which the server has taken
// (it no longer asks), is dropped. level is the server's protocol level; an
// answer below 2 cannot carry an instruction, and one that does is refused.
func (a *Agent) Answered(_ context.Context, level int, s *agentproto.SignedTrust) {
	if s == nil {
		a.setReport(nil)
		return
	}
	if level < 2 {
		a.Log.Warn("refused a trust instruction from a server that does not speak protocol level 2")
		return
	}
	p, err := agentproto.VerifyTrust(a.Key(), *s, a.DeviceID, a.origin(), a.now())
	if err != nil {
		a.Log.Warn("refused a trust instruction", "error", err)
		if errors.Is(err, agentproto.ErrTrustSignature) || p.ID == "" || len(p.ID) > 64 {
			// Nothing in it is authentic: it is not echoed to the server.
			return
		}
		a.setReport(&agentproto.TrustReport{ID: p.ID, Refused: reason(err), Trusts: a.trusts()})
		return
	}
	log := a.Store.LoadTrustLog()
	for _, h := range log.Handled {
		if h.ID == p.ID {
			// Sent again because its report has not arrived: report again,
			// and change nothing twice.
			var r agentproto.TrustReport
			if json.Unmarshal(h.Report, &r) == nil {
				r.Trusts = a.trusts()
				a.setReport(&r)
			}
			return
		}
	}
	if p.IssuedAt.Before(log.Issued) {
		a.Log.Warn("refused a trust instruction issued before one already handled", "id", p.ID)
		a.setReport(&agentproto.TrustReport{ID: p.ID, Refused: "issued before an instruction already handled", Trusts: a.trusts()})
		return
	}
	rep := a.carryOut(p)
	if rep.Refused != "" {
		a.Log.Warn("a trust instruction was not carried out", "id", p.ID, "reason", rep.Refused)
		a.setReport(&rep)
		return
	}
	b, _ := json.Marshal(rep)
	log.Issued = p.IssuedAt
	log.Handled = append(log.Handled, state.TrustHandled{ID: p.ID, Issued: p.IssuedAt, Report: b})
	if len(log.Handled) > keepHandled {
		log.Handled = log.Handled[len(log.Handled)-keepHandled:]
	}
	if err := a.Store.SaveTrustLog(log); err != nil {
		a.Log.Error("saving the trust log failed", "error", err)
	}
	a.setReport(&rep)
}

// carryOut verifies the chains of an instruction that verified, and widens the
// agent's trust when its target chains pass.
func (a *Agent) carryOut(p agentproto.TrustPayload) agentproto.TrustReport {
	rep := agentproto.TrustReport{ID: p.ID}
	refuse := func(format string, args ...any) agentproto.TrustReport {
		rep.Refused = fmt.Sprintf(format, args...)
		rep.Trusts = a.trusts()
		return rep
	}
	// What the agent would trust: the system's roots, its CA file and the
	// certificates the instruction adds.
	pool := x509.NewCertPool()
	existing, err := a.caFilePEM()
	if err != nil {
		return refuse("reading the CA file: %v", err)
	}
	pool.AppendCertsFromPEM(existing)
	add := make([]*x509.Certificate, 0, len(p.AddCerts))
	for _, s := range p.AddCerts {
		c, err := agentproto.DecodeTrustCert(s)
		if err != nil {
			return refuse("a certificate to add: %v", err)
		}
		// Only a certificate authority's: nothing else can anchor a chain,
		// and a leaf added as a root would trust one server's key by itself.
		if !c.IsCA || !c.BasicConstraintsValid {
			return refuse("a certificate to add is not a certificate authority's")
		}
		pool.AddCert(c)
		add = append(add, c)
	}
	targets, targetsOK := 0, true
	for _, c := range p.Chains {
		chain, err := parseChain(c)
		res := agentproto.TrustResult{Chain: c.ID, Scope: agentproto.TrustScopeAgent}
		if err == nil {
			err = a.Verifier.Verify(chain, p.Origin, true, pool)
		}
		if err != nil {
			res.Error = reason(err)
		}
		res.OK = err == nil
		if c.Purpose == agentproto.TrustTarget {
			targets++
			targetsOK = targetsOK && res.OK
		}
		rep.Results = append(rep.Results, res)
	}
	// The EasyPatch agent's host, against the system's roots alone: what that
	// agent trusts besides an authority its install carried.
	for _, c := range p.EasyPatchChains {
		chain, err := parseChain(c)
		res := agentproto.TrustResult{Chain: c.ID, Scope: agentproto.TrustScopeEasyPatch}
		if err == nil {
			err = a.Verifier.Verify(chain, p.EasyPatchHost, true, nil)
		}
		if err != nil {
			res.Error = reason(err)
		}
		res.OK = err == nil
		rep.Results = append(rep.Results, res)
	}
	if targets > 0 && targetsOK {
		if err := a.widen(existing, add); err != nil {
			return refuse("widening the trust failed: %v", err)
		}
	}
	rep.Widened = a.Config.TrustSystem && a.Config.CAFile != ""
	rep.Trusts = a.trusts()
	return rep
}

func (a *Agent) caFilePEM() ([]byte, error) {
	if a.Config.CAFile == "" {
		return nil, nil
	}
	return os.ReadFile(a.Config.CAFile)
}

// widen makes the agent trust the system's roots and its CA file together,
// the file now holding the certificates added too. The file is written whole
// before the configuration points at it, and the running client follows only
// when both are saved.
func (a *Agent) widen(existing []byte, add []*x509.Certificate) error {
	if a.Config.CAFile == "" && len(add) == 0 {
		return nil // the system's roots alone already are the trust
	}
	bundle := bytes.TrimRight(existing, "\n")
	if len(bundle) > 0 {
		bundle = append(bundle, '\n')
	}
	for _, c := range add {
		if hasCert(existing, c) {
			continue
		}
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	next := *a.Config
	next.TrustSystem = true
	if !bytes.Equal(bundle, existing) || a.Config.CAFile == "" {
		path, err := a.Store.SaveCA(bundle)
		if err != nil {
			return err
		}
		next.CAFile = path
	}
	if next == *a.Config {
		return nil
	}
	if err := a.Store.SaveConfig(&next); err != nil {
		return err
	}
	*a.Config = next
	if err := a.Client.Retrust(next.CAFile, next.TrustSystem); err != nil {
		// Saved: the next start trusts it. This process keeps what it has.
		a.Log.Error("the agent's trust is widened but this process could not follow; it will at the next start", "error", err)
	}
	return nil
}

// hasCert reports whether the PEM bundle already holds c.
func hasCert(bundle []byte, c *x509.Certificate) bool {
	for {
		var b *pem.Block
		b, bundle = pem.Decode(bundle)
		if b == nil {
			return false
		}
		if b.Type == "CERTIFICATE" && bytes.Equal(b.Bytes, c.Raw) {
			return true
		}
	}
}
