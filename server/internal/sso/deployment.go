package sso

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// DeploymentProviderID is the id of the provider the deployment sets up
// (ADR-0044). It is fixed so that the deployment's provider can send people
// to its start URL: Authentik's enrollment flow ends there
// (docker/authentik/easyrmm.yaml).
var DeploymentProviderID = uuid.MustParse("b2927669-72ce-48a1-a83d-8215013be7ab")

// ErrManaged refuses changes to the deployment's provider.
var ErrManaged = apperr.Conflict("provider_managed",
	"This provider is set up by the deployment. Change it in the server's configuration (deploy/.env), not here.")

// Deployment is a provider the deployment configures, rather than a super
// administrator: Authentik when setup.sh --with-authentik chose it. Its
// addresses are managed (Authentik's administrator sets them and people
// cannot change them) and it requires a second factor, so both are trusted.
type Deployment struct {
	Name         string
	Issuer       string
	ClientID     string
	ClientSecret string
	// Domains are the email domains it may sign in.
	Domains []string
	// Client reaches the provider: over loopback, through EasyRMM's own
	// edge, for Authentik. Nil uses the default client.
	Client *http.Client
}

// fallbackName names the deployment's provider when an administrator's
// provider already has its name.
func fallbackName(name string) string { return name + " (deployment)" }

// UseDeployment makes the deployment's provider match its configuration at
// start-up: created, changed or left alone, and audited when it changes.
// Nil means the deployment has none any more: a provider it set up before
// is kept, disabled and no longer managed, so a super administrator can
// delete it, and the identities linked through it stay until then.
func (s *Service) UseDeployment(ctx context.Context, d *Deployment) error {
	id := DeploymentProviderID
	if d == nil {
		s.mu.Lock()
		delete(s.clients, id)
		delete(s.cache, id)
		s.mu.Unlock()
		return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE identity_providers SET managed = false, enabled = false, updated_at = now()
				WHERE id = $1 AND managed`, id)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			return s.audit.Write(ctx, tx, audit.Event{Actor: audit.SystemActor("deployment"), Action: "sso.provider_update",
				TargetType: "identity_provider", TargetID: id.String(), Outcome: audit.Success,
				Details: map[string]any{"enabled": false, "managed": false, "reason": "no longer part of the deployment"}})
		})
	}
	in := ProviderInput{Name: d.Name, Issuer: d.Issuer, ClientID: d.ClientID, ClientSecret: d.ClientSecret,
		AllowedDomains: d.Domains, TrustEmail: true, TrustMFA: true, Enabled: true}
	if err := s.validate(&in, true).Err(); err != nil {
		return err
	}
	if d.Client != nil {
		s.mu.Lock()
		s.clients[id] = d.Client
		s.mu.Unlock()
	}
	stored, err := s.load(ctx, id)
	if err != nil && !errors.Is(err, apperr.ErrNotFound) {
		return err
	}
	if stored != nil && stored.Managed && s.unchanged(stored, in) {
		return nil
	}
	sealed, err := s.sealer.Seal([]byte(in.ClientSecret), secretAD(id))
	if err != nil {
		return err
	}
	action := "sso.provider_create"
	if stored != nil {
		action = "sso.provider_update"
	}
	write := func(name string) error {
		return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO identity_providers
					(id, name, issuer, client_id, client_secret_sealed, allowed_domains, trust_email, trust_mfa, enabled, managed)
				VALUES ($1, $2, $3, $4, $5, $6, true, true, true, true)
				ON CONFLICT (id) DO UPDATE SET name = $2, issuer = $3, client_id = $4, client_secret_sealed = $5,
					allowed_domains = $6, trust_email = true, trust_mfa = true, enabled = true, managed = true, updated_at = now()`,
				id, name, in.Issuer, in.ClientID, sealed, in.AllowedDomains); err != nil {
				return err
			}
			details := providerDetails(in)
			details["name"] = name
			details["managed"] = true
			return s.audit.Write(ctx, tx, audit.Event{Actor: audit.SystemActor("deployment"), Action: action,
				TargetType: "identity_provider", TargetID: id.String(), Outcome: audit.Success, Details: details})
		})
	}
	err = write(in.Name)
	if nameTaken(err) {
		err = write(fallbackName(in.Name))
	}
	return err
}

// unchanged reports whether the stored provider already is what the
// deployment configures.
func (s *Service) unchanged(p *providerRow, in ProviderInput) bool {
	if (p.Name != in.Name && p.Name != fallbackName(in.Name)) || p.Issuer != in.Issuer || p.ClientID != in.ClientID ||
		!slices.Equal(p.AllowedDomains, in.AllowedDomains) || !p.TrustEmail || !p.TrustMFA || !p.Enabled {
		return false
	}
	secret, err := s.sealer.Open(p.sealed, secretAD(p.ID))
	return err == nil && string(secret) == in.ClientSecret
}
