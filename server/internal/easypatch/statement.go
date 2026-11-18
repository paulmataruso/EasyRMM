package easypatch

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// Statements to the patching engine (one-product plan, phase B2). When
// EasyPatch runs inside EasyRMM's deployment, EasyRMM calls it with a short
// statement per request in StatementHeader: a JWT, HS256 with a key both
// programs read from the deployment, that names who acts, the role and the
// organizations that one call may use, and the method and request target it
// was made for. EasyPatch's EasyRmm scheme
// (easypatch/backend/API/Security/EasyRmmAuthentication.cs) accepts it only
// for that request, for StatementLifetime, and still applies its own role
// and tenant checks to what it says. EasyRMM decides who may do what before
// it signs; a statement carries only what one call needs.

// StatementHeader carries a statement.
const StatementHeader = "X-EasyRMM-Assertion"

// StatementLifetime is how long a statement is good for. EasyPatch refuses
// any that claims more than a minute.
const StatementLifetime = 30 * time.Second

// ServiceSubject is the subject of EasyRMM's own work, with no person behind
// it: provisioning, link checks, installs.
const ServiceSubject = "service"

// MinStatementKey is the shortest gateway key accepted, in bytes.
const MinStatementKey = 32

// Statement is what EasyRMM says about one call.
type Statement struct {
	// Subject is the EasyRMM user's id, or ServiceSubject.
	Subject string
	// Name is who EasyPatch's audit trail names (it records
	// "easyrmm:<Name>").
	Name string
	// Role is the role this call needs: RoleReadOnly, RoleAdmin or
	// RoleSuperAdmin.
	Role string
	// AllOrganizations lets the call touch every organization; otherwise
	// only Organizations (EasyPatch's ids), and none if that is empty.
	AllOrganizations bool
	Organizations    []uuid.UUID
}

// statementKey carries a call's statement in its context.
type statementKey struct{}

// WithStatement returns ctx carrying s, the statement for calls to the
// engine made with it. Calls without one act as EasyRMM itself
// (ServiceSubject) with RoleAdmin in every organization, as the
// connector's API token does, named after whom they are for, if anyone.
func WithStatement(ctx context.Context, s Statement) context.Context {
	return context.WithValue(ctx, statementKey{}, s)
}

// statementFor is the statement for a call made with ctx.
func statementFor(ctx context.Context, onBehalfOf string) Statement {
	if s, ok := ctx.Value(statementKey{}).(Statement); ok {
		return s
	}
	name := "EasyRMM"
	if onBehalfOf != "" {
		name = cut(onBehalfOf, 254)
	}
	return Statement{Subject: ServiceSubject, Name: name, Role: RoleAdmin, AllOrganizations: true}
}

// Signer makes statements with the gateway key.
type Signer struct {
	key []byte
	now func() time.Time
}

// NewSigner returns a signer for key, which must be at least MinStatementKey
// bytes.
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < MinStatementKey {
		return nil, fmt.Errorf("easypatch: the gateway key must be at least %d bytes", MinStatementKey)
	}
	return &Signer{key: append([]byte(nil), key...), now: time.Now}, nil
}

// statementHeader is the JOSE header of every statement, encoded once.
var statementHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"easyrmm-gateway+jwt"}`))

type statementClaims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	// Orgs is "*" or a list of EasyPatch organization ids.
	Orgs     any    `json:"orgs"`
	Method   string `json:"htm"`
	Target   string `json:"htu"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

// Sign returns the statement s for one request: method and target are the
// request's method and its path with query, exactly as sent.
func (g *Signer) Sign(s Statement, method, target string) (string, error) {
	// The engine refuses control characters and long names; an audit name
	// is not worth failing a call over.
	s.Name = cut(strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s.Name)), 254)
	switch {
	case s.Subject == "" || len(s.Subject) > 128 || s.Name == "":
		return "", errors.New("easypatch: a statement needs a subject and a name")
	case s.Role != RoleReadOnly && s.Role != RoleAdmin && s.Role != RoleSuperAdmin:
		return "", fmt.Errorf("easypatch: %q is not an EasyPatch role", s.Role)
	case method == "" || target == "" || target[0] != '/':
		return "", errors.New("easypatch: a statement needs the request's method and target")
	}
	var orgs any = "*"
	if !s.AllOrganizations {
		ids := make([]string, len(s.Organizations))
		for i, id := range s.Organizations {
			ids[i] = id.String()
		}
		orgs = ids
	}
	now := g.now()
	payload, err := json.Marshal(statementClaims{
		Issuer: "easyrmm", Audience: "easypatch", Subject: s.Subject, Name: s.Name, Role: s.Role, Orgs: orgs,
		Method: method, Target: target, IssuedAt: now.Unix(), Expires: now.Add(StatementLifetime).Unix(),
	})
	if err != nil {
		return "", err
	}
	signing := statementHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, g.key)
	mac.Write([]byte(signing))
	return signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
