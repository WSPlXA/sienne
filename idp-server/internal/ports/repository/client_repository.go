package repository

import (
	"context"

	"idp-server/internal/domain/client"
)

type ClientRepository interface {
	FindByClientID(ctx context.Context, clientID string) (*client.Model, error)
	CreateClient(ctx context.Context, model *client.Model) error
	RegisterRedirectURIs(ctx context.Context, clientDBID int64, redirectURIs []string) (int, error)
	RegisterPostLogoutRedirectURIs(ctx context.Context, clientDBID int64, redirectURIs []string) (int, error)
}
