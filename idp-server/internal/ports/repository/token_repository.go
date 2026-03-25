package repository

import (
	"context"
	"time"

	tokendomain "idp-server/internal/domain/token"
)

type TokenRepository interface {
	CreateAccessToken(ctx context.Context, model *tokendomain.AccessToken) error
	CreateRefreshToken(ctx context.Context, model *tokendomain.RefreshToken) error
	FindActiveAccessTokenBySHA256(ctx context.Context, tokenSHA256 string) (*tokendomain.AccessToken, error)
	FindActiveRefreshTokenBySHA256(ctx context.Context, tokenSHA256 string) (*tokendomain.RefreshToken, error)
	RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, revokedAt time.Time, newToken *tokendomain.RefreshToken) error
}
