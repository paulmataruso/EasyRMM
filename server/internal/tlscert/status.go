package tlscert

import (
	"context"
	"time"
)

// States a name is shown in.
const (
	StateValid      = "valid"
	StateRenewing   = "renewing"
	StateWaitingDNS = "waiting_dns"
	StateFailing    = "failing"
	StateExpired    = "expired"
	StatePending    = "pending" // no certificate yet, nothing failed
)

// NameStatus is what the Certificates page shows for one name. It carries no
// key and no credential.
type NameStatus struct {
	Name            string     `json:"name"`
	Role            string     `json:"role"` // "remote access" for MeshCentral's name
	State           string     `json:"state"`
	Imported        bool       `json:"imported"`
	Serial          string     `json:"serial,omitempty"`
	Issuer          string     `json:"issuer,omitempty"`
	NotBefore       *time.Time `json:"notBefore,omitempty"`
	NotAfter        *time.Time `json:"notAfter,omitempty"`
	RenewalDue      *time.Time `json:"renewalDue,omitempty"`
	AriStart        *time.Time `json:"ariStart,omitempty"`
	AriEnd          *time.Time `json:"ariEnd,omitempty"`
	AriExplanation  string     `json:"ariExplanation,omitempty"`
	NextAttemptAt   *time.Time `json:"nextAttemptAt,omitempty"`
	FailingSince    *time.Time `json:"failingSince,omitempty"`
	WaitingDNSSince *time.Time `json:"waitingDnsSince,omitempty"`
	LastError       string     `json:"lastError,omitempty"`
	Failures        int        `json:"failures"`
	Alert           string     `json:"alert"`
	AlertReason     string     `json:"alertReason,omitempty"`
	// RetryRefusedUntil is set while Retry now would be refused.
	RetryRefusedUntil *time.Time `json:"retryRefusedUntil,omitempty"`
	// MeshCentral's name: the serial served, and the one waiting.
	ServedSerial   string     `json:"servedSerial,omitempty"`
	PendingSerial  string     `json:"pendingSerial,omitempty"`
	PendingReadyAt *time.Time `json:"pendingReadyAt,omitempty"`
}

// Status is the page's data.
type Status struct {
	Directory string       `json:"directory"`
	Email     string       `json:"email"` // the account's own address, or empty for none
	Account   bool         `json:"account"`
	Held      bool         `json:"held"`
	Names     []NameStatus `json:"names"`
	Warnings  []string     `json:"warnings"`
	Now       time.Time    `json:"now"`
}

func tp(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// Status returns the state of every name.
func (s *Service) Status(ctx context.Context) (Status, error) {
	rows, err := s.loadRows(ctx)
	if err != nil {
		return Status{}, err
	}
	now := s.deps.Now()
	s.mu.Lock()
	ready := s.accountReady
	busy := map[string]bool{}
	for n := range s.inflight {
		busy[n] = true
	}
	s.mu.Unlock()
	st := Status{Directory: s.set.Directory, Email: s.set.Email, Account: ready, Held: s.deps.Held(), Now: now, Warnings: append([]string{}, s.set.Warnings...), Names: []NameStatus{}}
	for _, r := range rows {
		level, reason := alertFor(r, now)
		due, _ := renewalWindow(r)
		n := NameStatus{Name: r.Name, Imported: r.Imported, Serial: r.Serial, Issuer: r.Issuer, NotBefore: tp(r.NotBefore), NotAfter: tp(r.NotAfter),
			RenewalDue: tp(due), AriStart: tp(r.AriStart), AriEnd: tp(r.AriEnd), AriExplanation: r.AriExplanation,
			NextAttemptAt: tp(r.NextAttemptAt), FailingSince: tp(r.FailingSince), WaitingDNSSince: tp(r.WaitingDNSSince), LastError: r.LastError,
			Failures: r.Failures, Alert: level, AlertReason: reason, ServedSerial: r.ServedSerial, PendingSerial: r.PendingSerial, PendingReadyAt: tp(r.PendingReadyAt)}
		if r.Name == s.set.MeshName {
			n.Role = "remote access"
			if served, pending, ready := s.slot.State(); served != "" {
				n.ServedSerial, n.PendingSerial, n.PendingReadyAt = served, pending, tp(ready)
			}
		}
		switch {
		case busy[r.Name]:
			n.State = StateRenewing
		case r.HasCertificate() && !now.Before(r.NotAfter):
			n.State = StateExpired
		case !r.WaitingDNSSince.IsZero() && !r.HasCertificate():
			n.State = StateWaitingDNS
		case !r.FailingSince.IsZero():
			n.State = StateFailing
		case r.HasCertificate():
			n.State = StateValid
		default:
			n.State = StatePending
		}
		if ok, at := withinBudget(r.FailedAt, retryBudget, now); !ok {
			n.RetryRefusedUntil = tp(at)
		}
		st.Names = append(st.Names, n)
	}
	return st, nil
}
