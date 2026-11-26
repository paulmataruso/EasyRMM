package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/addrpolicy"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
)

// Message is what a delivery carries, as data: no secrets (ADR-0053).
type Message struct {
	Subject string      `json:"subject"`
	Summary string      `json:"summary"`
	Notice  *NoticeBody `json:"notice,omitempty"`
}

// NoticeBody is a notice as a webhook receives it.
type NoticeBody struct {
	ID             uuid.UUID  `json:"id"`
	Kind           string     `json:"kind"`
	Title          string     `json:"title"`
	Detail         string     `json:"detail"`
	OrganizationID *uuid.UUID `json:"organizationId,omitempty"`
	OpenedAt       time.Time  `json:"openedAt"`
}

// testMessage is the test's text: EasyRMM's own words, no channel name and
// nothing anyone typed.
var testMessage = Message{
	Subject: "EasyRMM test notification",
	Summary: "This is a test notification from EasyRMM. If you are reading it, notifications to this channel work.",
}

// loaded is a channel as the sender reads it, under the owner's scope.
type loaded struct {
	kind         string
	enabled      bool
	recipients   []string
	host         string
	port         int
	sealedURL    string
	sealedSecret string
	authority    string
	legacy       bool
	generation   int64
	approved     []string
	pending      []string
}

func (s *Service) load(ctx context.Context, d *delivery) (*loaded, error) {
	l := &loaded{}
	err := s.db.ReadTx(ctx, ownerScope(d.owner), func(tx pgx.Tx) error {
		var host, sealedURL, sealedSecret, authority *string
		var port *int
		var aState, aHost *string
		var aPort *int
		var prefixes []string
		if err := tx.QueryRow(ctx, `SELECT c.kind, c.enabled, d.recipients, d.webhook_host, d.webhook_port, d.sealed_url, d.sealed_secret,
				d.trusted_authority, d.legacy_headers, d.generation, a.state, a.host, a.port, a.prefixes
			FROM notification_channels c JOIN notification_channel_details d ON d.channel_id = c.id
			LEFT JOIN notification_channel_approvals a ON a.channel_id = c.id WHERE c.id = $1`, d.channel).
			Scan(&l.kind, &l.enabled, &l.recipients, &host, &port, &sealedURL, &sealedSecret, &authority, &l.legacy, &l.generation, &aState, &aHost, &aPort, &prefixes); err != nil {
			return err
		}
		l.host, l.port = deref(host), derefInt(port)
		l.sealedURL, l.sealedSecret, l.authority = deref(sealedURL), deref(sealedSecret), deref(authority)
		if aState != nil && *aState == "approved" && deref(aHost) == l.host && derefInt(aPort) == l.port {
			l.approved = prefixes
		}
		rows, err := tx.Query(ctx, `SELECT recipient FROM notification_delivery_recipients WHERE delivery_id = $1 AND status = 'pending' ORDER BY recipient`, d.id)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r string
			if err := rows.Scan(&r); err != nil {
				return err
			}
			l.pending = append(l.pending, r)
		}
		return rows.Err()
	})
	return l, err
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt(n *int) int {
	if n == nil {
		return 0
	}
	return *n
}

// recipientResult is what became of one recipient: status is sent, failed or
// pending (to be tried again).
type recipientResult struct {
	status, err, reply string
}

// result is how an attempt went.
type result struct {
	// hard: an answer that marks the channel failing at once (401, 403, 404, 410).
	hard bool
	// approval: refused by the address policy until a super administrator approves.
	approval bool
	// retryAfter is the receiver's or the mail server's own wait.
	retryAfter time.Duration
	err        string
	reply      string
	recips     map[string]recipientResult
	// mailFailure: the mail server could not be connected to or signed in to.
	mailFailure bool
	mailOK      bool
}

// Webhook status classes (ADR-0053, "Order per channel, and per subject").
func transientStatus(code int) bool {
	switch code {
	case 408, 425, 429:
		return true
	}
	return code >= 500
}

func hardStatus(code int) bool { return code == 401 || code == 403 || code == 404 || code == 410 }

// retryAfterOf reads a Retry-After header in seconds, up to an hour.
func retryAfterOf(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if n, err := strconv.Atoi(h); err == nil && n > 0 {
		return min(time.Duration(n)*time.Second, RetryMax)
	}
	if t, err := http.ParseTime(h); err == nil && t.After(now) {
		return min(t.Sub(now), RetryMax)
	}
	return 0
}

// describe turns a failed request into one of EasyRMM's own sentences,
// naming the host: never a URL's path or query (Go's *url.Error prints the
// whole URL, so it is unwrapped to its cause), never a response body.
func describe(err error, host string) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var cve *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var rec tls.RecordHeaderError
	var nerr net.Error
	switch {
	case errors.Is(err, addrpolicy.ErrRefused):
		return clip(err.Error(), 300)
	case errors.As(err, &cve), errors.As(err, &unknown), errors.As(err, &hostErr), errors.As(err, &invalid):
		return fmt.Sprintf("The receiver at %s presented a certificate EasyRMM does not trust. Give the channel the certificate authority that issued it.", host)
	case errors.As(err, &rec):
		return fmt.Sprintf("The receiver at %s did not answer with TLS.", host)
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &nerr) && nerr.Timeout()):
		return fmt.Sprintf("The receiver at %s did not answer in time.", host)
	case errors.Is(err, context.Canceled):
		return "EasyRMM stopped before the receiver answered."
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return fmt.Sprintf("EasyRMM could not connect to %s.", host)
	}
	if strings.Contains(err.Error(), "could not be resolved") || strings.Contains(err.Error(), "has no address") {
		return clip(err.Error(), 300)
	}
	return fmt.Sprintf("The request to %s failed.", host)
}

// webhookBody is the generic body (ADR-0053, "The signature"): the engine's
// fields, with source and notice.
func (s *Service) webhookBody(d *delivery, m Message, at time.Time) ([]byte, error) {
	body := map[string]any{
		"event": d.event, "deliveryId": d.id.String(), "sentAt": at.UTC().Format(time.RFC3339),
		"subject": m.Subject, "summary": m.Summary, "source": "easyrmm",
		"alerts": []any{}, "moreCount": 0, "consoleUrl": s.consoleURL,
	}
	if m.Notice != nil {
		body["notice"] = m.Notice
	}
	return json.Marshal(body)
}

// Sign is the signature header: t=<unix seconds>,v1=<hex HMAC-SHA256(key, t
// + "." + body)>, the engine's scheme under EasyRMM's name.
func Sign(secret string, at time.Time, body []byte) string {
	t := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(t + "."))
	mac.Write(body)
	return "t=" + t + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) policy(owner uuid.UUID, approved []string) (addrpolicy.Policy, error) {
	p := addrpolicy.Policy{Mode: addrpolicy.Organization, Env: s.env.Snapshot(), Resolve: s.resolve}
	if owner == uuid.Nil {
		p.Mode = addrpolicy.Platform
		return p, nil
	}
	ps, err := addrpolicy.ParsePrefixes(approved)
	p.Approved = ps
	return p, err
}

func (s *Service) sendWebhook(ctx context.Context, d *delivery, l *loaded) result {
	fail := func(msg string) result {
		return result{err: msg, recips: map[string]recipientResult{webhookRecipient: {status: StatusPending, err: msg}}}
	}
	rawURL, err := s.sealer.Open(l.sealedURL, urlAD(d.channel))
	if err != nil {
		return fail("EasyRMM could not open the channel's sealed web address.")
	}
	secret, err := s.sealer.Open(l.sealedSecret, secretAD(d.channel))
	if err != nil {
		return fail("EasyRMM could not open the channel's sealed signing secret.")
	}
	var m Message
	if err := json.Unmarshal(d.message, &m); err != nil {
		return result{err: "The message could not be read.", recips: map[string]recipientResult{webhookRecipient: {status: StatusFailed, err: "The message could not be read."}}}
	}
	pol, err := s.policy(d.owner, l.approved)
	if err != nil {
		return fail("The approved networks could not be read.")
	}
	client, err := s.clientFor(d.channel, l.generation, pol, []byte(l.authority))
	if err != nil {
		return fail(err.Error())
	}
	at := s.now()
	body, err := s.webhookBody(d, m, at)
	if err != nil {
		return fail("The message could not be written.")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, string(rawURL), bytes.NewReader(body))
	if err != nil {
		return fail("The channel's web address is not usable.")
	}
	sig := Sign(string(secret), at, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "EasyRMM")
	req.Header.Set("X-EasyRMM-Event", d.event)
	req.Header.Set("X-EasyRMM-Delivery", d.id.String())
	req.Header.Set("X-EasyRMM-Signature", sig)
	if l.legacy {
		req.Header.Set("X-EasyPatch-Event", d.event)
		req.Header.Set("X-EasyPatch-Signature", sig)
	}
	resp, err := client.Do(req)
	if err != nil {
		msg := describe(err, l.host)
		return result{err: msg, approval: addrpolicy.NeedsApproval(unwrapURL(err)) && d.owner != uuid.Nil,
			recips: map[string]recipientResult{webhookRecipient: {status: StatusPending, err: msg}}}
	}
	// A response is read up to 64 KiB and discarded.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, ResponseLimit))
	_ = resp.Body.Close()
	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		return result{recips: map[string]recipientResult{webhookRecipient: {status: StatusSent}}}
	case transientStatus(code):
		msg := fmt.Sprintf("The receiver at %s answered %d.", l.host, code)
		return result{err: msg, retryAfter: retryAfterOf(resp.Header.Get("Retry-After"), at),
			recips: map[string]recipientResult{webhookRecipient: {status: StatusPending, err: msg}}}
	default:
		// 3xx is a failure too: no redirect is followed.
		msg := fmt.Sprintf("The receiver at %s answered %d.", l.host, code)
		if code >= 300 && code < 400 {
			msg = fmt.Sprintf("The receiver at %s answered %d, a redirect. EasyRMM does not follow redirects; use the final address.", l.host, code)
		}
		return result{err: msg, hard: hardStatus(code), recips: map[string]recipientResult{webhookRecipient: {status: StatusFailed, err: msg}}}
	}
}

func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// webhookRecipient is the one outcome row a webhook delivery has.
const webhookRecipient = "(webhook)"

// sendEmail sends to the recipients not yet accepted: one message each.
func (s *Service) sendEmail(ctx context.Context, d *delivery, l *loaded) result {
	res := result{recips: map[string]recipientResult{}}
	to := l.pending
	if len(to) == 0 {
		return res
	}
	if s.mail == nil {
		res.err = "EasyRMM has no mail server. Set one under Settings → Notifications → Mail server."
		return res
	}
	var m Message
	if err := json.Unmarshal(d.message, &m); err != nil {
		for _, r := range to {
			res.recips[r] = recipientResult{status: StatusFailed, err: "The message could not be read."}
		}
		return res
	}
	msg, err := mailer.Letter{Subject: m.Subject, Before: []string{m.Summary}}.Message()
	if err != nil {
		res.err = "The message could not be made."
		return res
	}
	msg.MessageID = func(rcpt string) string { return messageKey(d.id, rcpt) }
	outs, err := s.mail.SendNotification(ctx, to, msg)
	if err != nil {
		if ae, ok := apperr.As(err); ok {
			res.err = ae.Message
		} else {
			res.err = "The mail server could not be used."
			res.mailFailure = true
		}
		return res
	}
	for _, o := range outs {
		var re *mailer.ReplyError
		var lim mailer.Limited
		switch {
		case o.Err == nil:
			res.recips[o.To] = recipientResult{status: StatusSent, reply: o.Reply}
			res.mailOK = true
		case errors.As(o.Err, &lim):
			// The rate limit is the platform's: retried after the wait, never the recipient's failure.
			res.recips[o.To] = recipientResult{status: StatusPending, err: "Waiting for room under the mail server's limit."}
			res.retryAfter = max(res.retryAfter, lim.RetryIn())
		case errors.As(o.Err, &re):
			rr := recipientResult{reply: clip(re.Error(), 400)}
			if re.Permanent() {
				rr.status, rr.err = StatusFailed, "The mail server refused the message."
			} else {
				rr.status, rr.err = StatusPending, "The mail server asked EasyRMM to try again later."
			}
			if re.Step == "sign-in" || re.Step == "hello" || re.Step == "STARTTLS" {
				res.mailFailure = true
				rr.status, rr.err = StatusPending, "The mail server refused EasyRMM's sign-in."
			}
			res.recips[o.To] = rr
			if res.reply == "" {
				res.reply = rr.reply
			}
		default:
			res.recips[o.To] = recipientResult{status: StatusPending, err: "The mail server could not be reached."}
			res.mailFailure = true
		}
	}
	for _, r := range res.recips {
		if r.err != "" {
			res.err = r.err
			break
		}
	}
	return res
}

// The mail server's circuit: after 5 failures in a row to connect or sign
// in, notification email pauses for a minute, doubling to 15. Webhooks go on.
type circuitState struct {
	fails int
	pause time.Duration
	until time.Time
}

const (
	circuitAfter = 5
	circuitFirst = time.Minute
	circuitMax   = 15 * time.Minute
)

func (s *Service) mailPaused() bool {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	return s.now().Before(s.circuit.until)
}

func (s *Service) circuitRecord(failed, ok bool) {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	c := &s.circuit
	switch {
	case ok:
		*c = circuitState{}
	case failed:
		c.fails++
		if c.fails >= circuitAfter {
			if c.pause == 0 {
				c.pause = circuitFirst
			} else {
				c.pause = min(c.pause*2, circuitMax)
			}
			c.until = s.now().Add(c.pause)
		}
	}
}

// netLookup resolves a name with the system resolver.
func netLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return netResolver.LookupNetIP(ctx, "ip", host)
}

var netResolver = &net.Resolver{}
