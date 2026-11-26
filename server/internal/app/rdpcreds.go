package app

import (
	"context"

	"github.com/paulmataruso/easyrmm/server/internal/rdpcreds"
	"github.com/paulmataruso/easyrmm/server/internal/remote"
)

// rdpOpener lets the remote gateway open saved RDP credentials (ADR-0079).
type rdpOpener struct{ svc *rdpcreds.Service }

func (o rdpOpener) OpenRDPCredential(ctx context.Context, u remote.CredentialUse) (*remote.OpenedCredential, error) {
	c, err := o.svc.OpenForSession(ctx, rdpcreds.Use(u))
	if err != nil {
		return nil, err
	}
	return &remote.OpenedCredential{Domain: c.Domain, Username: c.Username, Password: c.Password}, nil
}
