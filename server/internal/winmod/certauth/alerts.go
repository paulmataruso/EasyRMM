package certauth

import (
	"encoding/json"
	"fmt"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/monitoring"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

// ADR-0076 section 3's alert kinds that status and ca_findings serve.
// ca_certificate_revoked needs the Security log's event 4870 and waits for the
// events slice. ca_findings_present is ca_findings_new of the ADR without its
// baseline: see docs/notes/roles2.md.
const (
	KindCertificateExpiring = "ca_certificate_expiring"
	KindCRLExpiring         = "ca_crl_expiring"
	KindServiceStopped      = "ca_service_stopped"
	KindFindingsPresent     = "ca_findings_present"
)

// Alerts name the CA and a count, never a subject or requester: alerts are
// visible to everyone who sees the device.
func statusOf(data json.RawMessage) (Status, error) {
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return st, monitoring.ErrUnknown
	}
	return st, nil
}

// AlertKinds are the certificate authority alerts monitoring registers.
func AlertKinds() monitoring.ModuleAlerts {
	days := monitoring.ThresholdSpec{Used: true, Min: 1, Max: 100, Unit: "days"}
	return monitoring.ModuleAlerts{
		Module: modules.CertificateAuthority,
		Kinds: []monitoring.ModuleKind{{
			Name: KindCertificateExpiring, Label: "CA certificate expiring", Module: modules.CertificateAuthority,
			Action: "certificate_authority.status", Threshold: days, LowestWins: true,
			Eval: func(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
				st, err := statusOf(data)
				switch {
				case err != nil || threshold == nil:
					return monitoring.Verdict{}, monitoring.ErrUnknown
				case st.Certificate == nil:
					return monitoring.Verdict{NotApplicable: true}, nil
				}
				left := st.Certificate.DaysLeft
				return monitoring.Verdict{Holds: left <= *threshold, Value: float64(left),
					Detail: fmt.Sprintf("The CA certificate of %s ends in %d days.", st.CAName, left)}, nil
			},
		}, {
			Name: KindCRLExpiring, Label: "CA revocation list about to lapse", Module: modules.CertificateAuthority,
			Action:    "certificate_authority.status",
			Threshold: monitoring.ThresholdSpec{Used: true, Min: 1, Max: 100, Unit: "hours"},
			Eval: func(data json.RawMessage, threshold *int) (monitoring.Verdict, error) {
				st, err := statusOf(data)
				switch {
				case err != nil || threshold == nil:
					return monitoring.Verdict{}, monitoring.ErrUnknown
				case st.CRL == nil || st.CRL.HoursToBaseExpiry == nil:
					return monitoring.Verdict{NotApplicable: true}, nil
				}
				left := *st.CRL.HoursToBaseExpiry
				return monitoring.Verdict{Holds: left <= *threshold, Value: float64(left),
					Detail: fmt.Sprintf("The base revocation list of %s lapses in %d hours.", st.CAName, left)}, nil
			},
		},
			rolekit.ServiceStoppedKind(modules.CertificateAuthority, KindServiceStopped, "Certificate Services stopped", "certificate_authority.status",
				func(data json.RawMessage) (string, error) {
					st, err := statusOf(data)
					return st.ServiceState, err
				}),
			{
				Name: KindFindingsPresent, Label: "CA misconfiguration finding", Module: modules.CertificateAuthority,
				Action: "certificate_authority.ca_findings", MaxAge: 8 * 24 * 3600 * 1e9,
				Eval: func(data json.RawMessage, _ *int) (monitoring.Verdict, error) {
					var f Findings
					if err := json.Unmarshal(data, &f); err != nil {
						return monitoring.Verdict{}, monitoring.ErrUnknown
					}
					return monitoring.Verdict{Holds: len(f.Findings) > 0, Value: float64(len(f.Findings)),
						Detail: fmt.Sprintf("%s has %d misconfiguration finding(s).", f.CAName, len(f.Findings))}, nil
				},
			}},
		Defaults: []monitoring.DefaultPolicy{
			{Key: "expiring_90", Name: "Certificate authority: CA certificate expires within 90 days", Kind: KindCertificateExpiring,
				Threshold: intp(90), Severity: monitoring.SeverityWarning, Enabled: true,
				Description: "The CA certificate ends within 90 days: time to plan a renewal."},
			{Key: "expiring_14", Name: "Certificate authority: CA certificate expires within 14 days", Kind: KindCertificateExpiring,
				Threshold: intp(14), Severity: monitoring.SeverityCritical, Enabled: true,
				Description: "The CA certificate ends within 14 days."},
			{Key: "crl_lapsing", Name: "Certificate authority: CRL about to lapse", Kind: KindCRLExpiring,
				Threshold: intp(4), Severity: monitoring.SeverityCritical, Enabled: true,
				Description: "The base revocation list lapses within 4 hours: publication is failing, which breaks validation."},
			rolekit.ServiceStoppedDefault("service_stopped", "Certificate authority: service stopped", KindServiceStopped, 15, monitoring.SeverityCritical, true),
			{Key: "findings", Name: "Certificate authority: misconfiguration findings", Kind: KindFindingsPresent,
				Severity: monitoring.SeverityWarning, Enabled: false,
				Description: "The weekly check found at least one ESC1 to ESC8 finding. Off by default: a finding stays until it is fixed."},
		},
	}
}

func intp(n int) *int { return &n }
