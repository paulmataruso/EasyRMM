package app

import (
	"context"

	"github.com/paulmataruso/easyrmm/server/internal/notify"
	"github.com/paulmataruso/easyrmm/server/internal/tlscert"
)

// Notice kinds the certificate service raises (ADR-0055): one is open for a
// name at a time, at the level it has now.
const (
	noticeTLSWarning  = "tls_certificate_warning"
	noticeTLSCritical = "tls_certificate_critical"
)

// tlsNotices is the console's side of the certificate service's alert
// interface: a platform notice under the stable key tls:<name>. Until the
// notification sender's platform rules exist, the console is all there is
// behind it; they will read the same notices.
type tlsNotices struct{ n *notify.Service }

func (t tlsNotices) Publish(ctx context.Context, e tlscert.Event) error {
	if !e.Open {
		if err := t.n.ResolvePlatformNotice(ctx, noticeTLSWarning, e.Key); err != nil {
			return err
		}
		return t.n.ResolvePlatformNotice(ctx, noticeTLSCritical, e.Key)
	}
	kind, other, title := noticeTLSWarning, noticeTLSCritical, "A certificate needs attention: "+e.Name
	if e.Severity == tlscert.LevelCritical {
		kind, other, title = noticeTLSCritical, noticeTLSWarning, "A certificate is about to expire or has expired: "+e.Name
	}
	if err := t.n.ResolvePlatformNotice(ctx, other, e.Key); err != nil {
		return err
	}
	detail := e.Summary
	if e.LastError != "" {
		detail += " Last error: " + e.LastError
	}
	return t.n.RaisePlatformNotice(ctx, kind, e.Key, title, detail)
}
