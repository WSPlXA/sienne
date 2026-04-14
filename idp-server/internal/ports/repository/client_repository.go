package repository

import (
	"context"

	"idp-server/internal/domain/client"
)

// ClientRepository 定义 OAuth/OIDC 客户端注册信息的持久化接口。
type ClientRepository interface {
	FindByClientID(ctx context.Context, clientID string) (*client.Model, error)
	HasPostLogoutRedirectURI(ctx context.Context, clientDBID int64, redirectURI string) (bool, error)
	CreateClient(ctx context.Context, model *client.Model) error
	RegisterRedirectURIs(ctx context.Context, clientDBID int64, redirectURIs []string) (int, error)
	RegisterPostLogoutRedirectURIs(ctx context.Context, clientDBID int64, redirectURIs []string) (int, error)
}
