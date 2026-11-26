// Package certauth is the catalog of ADR-0076's certificate authority module:
// the CA's state, certificate and revocation lists, templates, the issued,
// pending, failed and revoked requests, approve and deny, revoke with a reason,
// publish the revocation list, and a read-only check for the ESC1 to ESC8
// misconfiguration classes (ca_findings).
//
// What is never here (ADR-0076, "Never exposed"): any CA private-key
// operation, CA install or renewal, editing of CDP and AIA, and creating or
// editing templates. The Go test TestCertutilVerbAllowlist fails any script
// that names a certutil verb off the list, and TestNoKeyOperations any word
// that would touch a key.
//
// Approving a request, revoking a certificate, and publishing a template that
// lets the requester name the subject of a certificate that can sign in, are
// tier 3: ca.manage, a confirmation of the computer's name, and a step-up. The
// last one is the dynamic tier of the ADR (template_publish refuses such a
// template and says to use template_publish_risky), so the server never has
// to read a template to know the tier.
package certauth

import (
	"embed"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

//go:embed scripts/*.ps1
var scriptFS embed.FS

// Tiers (ADR-0076, section 2).
const (
	tier0 = iota
	tier1
	tier2
	tier3
)

// CertSummary is the CA certificate as status shows it.
type CertSummary struct {
	Subject            string    `json:"subject"`
	Thumbprint         string    `json:"thumbprint"`
	NotAfter           time.Time `json:"notAfter"`
	DaysLeft           int       `json:"daysLeft"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	KeyLength          *int      `json:"keyLength"`
}

// CRLSummary is the revocation list as status shows it.
type CRLSummary struct {
	BaseThisUpdate    *time.Time `json:"baseThisUpdate"`
	BaseNextUpdate    *time.Time `json:"baseNextUpdate"`
	HoursToBaseExpiry *int       `json:"hoursToBaseExpiry"`
	DeltaNextUpdate   *time.Time `json:"deltaNextUpdate"`
}

// Counts are the numbers of requests by disposition.
type Counts struct {
	Pending int `json:"pending"`
	Issued  int `json:"issued"`
	Revoked int `json:"revoked"`
	Failed  int `json:"failed"`
}

// Status is certificate_authority.status's result.
type Status struct {
	CAName       string       `json:"caName"`
	CAType       string       `json:"caType"`
	Enterprise   bool         `json:"enterprise"`
	ServiceState string       `json:"serviceState"`
	Certificate  *CertSummary `json:"certificate"`
	CRL          *CRLSummary  `json:"crl"`
	Counts       *Counts      `json:"counts"`
}

// Certificate is one CA certificate.
type Certificate struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Thumbprint         string    `json:"thumbprint"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	DaysLeft           int       `json:"daysLeft"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	KeyLength          *int      `json:"keyLength"`
}

// Certificates is ca_certificate's result.
type Certificates struct {
	Certificates []Certificate `json:"certificates"`
}

// CRLInfo is one published revocation list.
type CRLInfo struct {
	ThisUpdate        *time.Time `json:"thisUpdate"`
	NextUpdate        *time.Time `json:"nextUpdate"`
	HoursToNextUpdate *int       `json:"hoursToNextUpdate"`
	SizeBytes         int64      `json:"sizeBytes"`
}

// CRLStatus is crl_status's and crl_publish's result.
type CRLStatus struct {
	Base  *CRLInfo `json:"base"`
	Delta *CRLInfo `json:"delta"`
}

// Template is one certificate template with the risk flags read from it.
type Template struct {
	Name                    string `json:"name"`
	DisplayName             string `json:"displayName"`
	SchemaVersion           int    `json:"schemaVersion"`
	Published               bool   `json:"published"`
	EnrolleeSuppliesSubject bool   `json:"enrolleeSuppliesSubject"`
	AuthenticationEku       bool   `json:"authenticationEku"`
	AnyPurpose              bool   `json:"anyPurpose"`
	ManagerApproval         bool   `json:"managerApproval"`
	LowPrivilegeEnroll      bool   `json:"lowPrivilegeEnroll"`
	Risky                   bool   `json:"risky"`
}

// Templates is template_list's and template_available's result.
type Templates struct {
	Standalone bool       `json:"standalone"`
	Templates  []Template `json:"templates"`
}

// Finding is one misconfiguration finding.
type Finding struct {
	ID       string `json:"id"`
	Class    string `json:"class"`
	Subject  string `json:"subject"`
	Evidence string `json:"evidence"`
}

// Findings is ca_findings' result. Notes say what was not checked.
type Findings struct {
	CAName   string    `json:"caName"`
	Findings []Finding `json:"findings"`
	Notes    []string  `json:"notes"`
}

// Request is one request or certificate.
type Request struct {
	ID            int64      `json:"id"`
	Requester     string     `json:"requester"`
	Template      string     `json:"template"`
	Submitted     *time.Time `json:"submitted"`
	Serial        string     `json:"serial"`
	NotAfter      *time.Time `json:"notAfter"`
	CommonName    string     `json:"commonName"`
	RevokedWhen   *time.Time `json:"revokedWhen"`
	RevokedReason *int       `json:"revokedReason"`
	Disposition   string     `json:"disposition"`
}

// Requests is requests_pending's and requests_list's result.
type Requests struct {
	Requests []Request `json:"requests"`
	Total    int       `json:"total"`
	Next     *int64    `json:"next"`
}

// RequestOne is request_get's result.
type RequestOne struct {
	Request Request `json:"request"`
}

// Disposed is the result of approving or denying a request.
type Disposed struct {
	ID          int64  `json:"id"`
	Disposition string `json:"disposition"`
}

// SerialDisposed is the result of revoking or reinstating a certificate.
type SerialDisposed struct {
	Serial      string `json:"serial"`
	Disposition string `json:"disposition"`
}

// TemplateDone is the result of publishing or unpublishing a template.
type TemplateDone struct {
	Name      string `json:"name"`
	Published bool   `json:"published"`
}

// Event is one certificate services audit event.
type Event struct {
	ID      int        `json:"id"`
	Time    *time.Time `json:"time"`
	Message string     `json:"message"`
}

// Activity is activity's result.
type Activity struct {
	Events []Event `json:"events"`
	Note   string  `json:"note"`
}

// RevocationReasons are the RFC 5280 reasons a certificate may be revoked for.
var RevocationReasons = []string{"unspecified", "key_compromise", "ca_compromise", "affiliation_changed", "superseded", "cessation_of_operation", "certificate_hold"}

var (
	serialPattern   = regexp.MustCompile(`^[0-9A-Fa-f]{2,40}$`)
	templatePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$`)
)

func device() winmod.Param {
	return winmod.Param{Name: "device", Type: winmod.Name, Required: true, Max: 64}
}

func serial(required bool) winmod.Param {
	return winmod.Param{Name: "serial", Type: winmod.Text, Required: required, Max: 40, Pattern: serialPattern}
}

func requestID(required bool) winmod.Param {
	return winmod.Param{Name: "id", Type: winmod.Int, Required: required, Min: 1}
}

func templateName() winmod.Param {
	return winmod.Param{Name: "name", Type: winmod.Text, Required: true, Max: 64, Pattern: templatePattern}
}

// oneOf refuses a request that gives both or neither of two parameters.
func oneOf(a, b string) func(map[string]any) error {
	return func(p map[string]any) error {
		_, hasA := p[a]
		_, hasB := p[b]
		if hasA == hasB {
			return rolekit.Invalid(a, "Give "+a+" or "+b+", not both and not neither.")
		}
		return nil
	}
}

func library(file string) string {
	b, err := scriptFS.ReadFile("scripts/" + file)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Script is the text of an action's script as the agent receives it.
func Script(file string) string {
	return strings.Replace(library(file+".ps1"), "#@library common\n", library("_common.ps1"), 1)
}

func entry(tier int, file, label string, timeout int, decode func(json.RawMessage) (json.RawMessage, error), params ...winmod.Param) winmod.Action {
	a := winmod.Action{
		Module: modules.CertificateAuthority, Name: "certificate_authority." + file, Label: label, Version: 1,
		Script: Script(file), ScriptSHA256: pins[file], Params: params, Timeout: timeout, Decode: decode,
	}
	switch tier {
	case tier0:
		a.Permission, a.Keep = rbac.PermCAView, time.Hour
	case tier1:
		a.Permission, a.Keep, a.Changes = rbac.PermCAManage, 7*24*time.Hour, true
	case tier2:
		a.Permission, a.Keep, a.Changes = rbac.PermCAManage, 7*24*time.Hour, true
		a.Confirm, a.Subject, a.SubjectIsDeviceName = true, "device", true
	case tier3:
		a.Permission, a.Keep, a.Changes = rbac.PermCAManage, 7*24*time.Hour, true
		a.Destructive, a.Subject, a.SubjectIsDeviceName = true, "device", true
	}
	return a
}

// sensitive marks a result that names requesters, subjects or people: it is
// opened by ca.view (which a Technician lacks), kept 15 minutes, and audited
// as a count.
func sensitive(a winmod.Action) winmod.Action {
	a.Sensitive, a.SensitivePermission, a.Keep = true, rbac.PermCAView, 15*time.Minute
	return a
}

// Actions are the certificate authority actions the server can run.
func Actions() []winmod.Action {
	status := entry(tier0, "status", "Read the certificate authority's state", 90, winmod.Typed[Status]())
	status.Freshness, status.Schedule = 5*time.Minute, time.Hour
	findings := entry(tier0, "ca_findings", "Check the CA for misconfiguration (ESC1 to ESC8)", 120, winmod.Typed[Findings]())
	findings.Freshness, findings.Schedule = time.Hour, 7*24*time.Hour
	findings.CountField = "findings"

	pending := sensitive(entry(tier0, "requests_pending", "List the pending requests", 60, winmod.Typed[Requests]()))
	pending.CountField = "requests"
	list := sensitive(entry(tier0, "requests_list", "List issued, revoked, failed and denied requests", 90, winmod.Typed[Requests](),
		winmod.Param{Name: "disposition", Type: winmod.Enum, Required: true, Values: []string{"issued", "revoked", "failed", "denied"}},
		winmod.Param{Name: "fromId", Type: winmod.Int, Min: 0}))
	list.CountField = "requests"
	get := sensitive(entry(tier0, "request_get", "Read one request or certificate", 30, winmod.Typed[RequestOne](), requestID(false), serial(false)))
	get.Check = oneOf("id", "serial")
	activity := sensitive(entry(tier0, "activity", "Read the certificate services audit events", 60, winmod.Typed[Activity]()))
	activity.CountField = "events"

	return []winmod.Action{
		status, findings,
		entry(tier0, "ca_certificate", "Read the CA certificate", 30, winmod.Typed[Certificates]()),
		entry(tier0, "crl_status", "Read the revocation lists", 60, winmod.Typed[CRLStatus]()),
		entry(tier0, "template_list", "List the templates this CA publishes", 60, winmod.Typed[Templates]()),
		entry(tier0, "template_available", "List the templates this CA could publish", 60, winmod.Typed[Templates]()),
		pending, list, get, activity,
		entry(tier1, "crl_publish", "Publish the revocation list", 120, winmod.Typed[CRLStatus](),
			winmod.Param{Name: "kind", Type: winmod.Enum, Required: true, Values: []string{"base", "delta"}}),
		entry(tier2, "template_publish", "Publish a template", 60, winmod.Typed[TemplateDone](), device(), templateName()),
		entry(tier3, "template_publish_risky", "Publish a template that lets the requester name the subject", 60, winmod.Typed[TemplateDone](), device(), templateName()),
		entry(tier2, "template_unpublish", "Unpublish a template", 60, winmod.Typed[TemplateDone](), device(), templateName()),
		entry(tier3, "request_approve", "Approve a pending request (issues a certificate)", 60, winmod.Typed[Disposed](), device(), requestID(true)),
		entry(tier2, "request_deny", "Deny a pending request", 60, winmod.Typed[Disposed](), device(), requestID(true)),
		entry(tier3, "certificate_revoke", "Revoke a certificate", 60, winmod.Typed[SerialDisposed](), device(), serial(true),
			winmod.Param{Name: "reason", Type: winmod.Enum, Required: true, Values: RevocationReasons},
			// The note is for the audit only; the script never reads it and the CA never sees it.
			winmod.Param{Name: "note", Type: winmod.Text, Max: 200}),
		entry(tier2, "certificate_unrevoke", "Reinstate a certificate on hold", 60, winmod.Typed[SerialDisposed](), device(), serial(true)),
	}
}
