package repository

import (
	"context"
	"time"

	tokendomain "idp-server/internal/domain/token"
)

// TokenRepository 是 access/refresh token 的数据库真相来源接口。
// 这里的能力偏“持久化与生命周期管理”，不负责 JWT 签发本身。
type TokenRepository interface {
	CreateAccessToken(ctx context.Context, model *tokendomain.AccessToken) error
	CreateRefreshToken(ctx context.Context, model *tokendomain.RefreshToken) error
	FindActiveAccessTokenBySHA256(ctx context.Context, tokenSHA256 string) (*tokendomain.AccessToken, error)
	FindActiveRefreshTokenBySHA256(ctx context.Context, tokenSHA256 string) (*tokendomain.RefreshToken, error)
	RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, revokedAt time.Time, newToken *tokendomain.RefreshToken) error
}
