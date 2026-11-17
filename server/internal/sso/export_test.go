package sso

import (
	"context"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/auth"
)

// ResolveClaims runs the linking rules on claims a provider might send.
// Dex reports every address as verified, so the unverified case is reached
// this way.
func (s *Service) ResolveClaims(ctx context.Context, providerID uuid.UUID, subject, email string, verified any) (uuid.UUID, string, error) {
	p, err := s.load(ctx, providerID)
	if err != nil {
		return uuid.Nil, "", err
	}
	id, _, code, err := s.resolve(ctx, p, claims{Subject: subject, Email: email, EmailVerified: verified}, normalizeEmail(email), auth.RequestMeta{})
	return id, code, err
}
