package token

import (
	"context"
	"testing"
	"time"

	clientdomain "idp-server/internal/domain/client"
	cacheport "idp-server/internal/ports/cache"
	pkgoauth2 "idp-server/pkg/oauth2"
)

type stubTokenCache struct {
	accessRevoked  bool
	refreshRevoked bool
}

func (s *stubTokenCache) SaveAccessToken(context.Context, cacheport.AccessTokenCacheEntry, time.Duration) error {
	return nil
}

func (s *stubTokenCache) GetAccessToken(context.Context, string) (*cacheport.AccessTokenCacheEntry, error) {
	return nil, nil
}

func (s *stubTokenCache) SaveRefreshToken(context.Context, cacheport.RefreshTokenCacheEntry, time.Duration) error {
	return nil
}

func (s *stubTokenCache) GetRefreshToken(context.Context, string) (*cacheport.RefreshTokenCacheEntry, error) {
	return nil, nil
}

func (s *stubTokenCache) RotateRefreshToken(context.Context, string, cacheport.RefreshTokenCacheEntry, time.Duration, time.Duration) error {
	return nil
}

func (s *stubTokenCache) RevokeAccessToken(context.Context, string, time.Duration) error {
	return nil
}

func (s *stubTokenCache) RevokeRefreshToken(context.Context, string, time.Duration) error {
	return nil
}

func (s *stubTokenCache) IsAccessTokenRevoked(context.Context, string) (bool, error) {
	return s.accessRevoked, nil
}

func (s *stubTokenCache) IsRefreshTokenRevoked(context.Context, string) (bool, error) {
	return s.refreshRevoked, nil
}

func TestExchangeRefreshTokenRejectsRevokedTokenFromCache(t *testing.T) {
	clientRepo := &stubTokenClientRepository{
		model: &clientdomain.Model{
			ID:                     7,
			ClientID:               "service-client",
			ClientSecretHash:       "hashed:service-secret",
			GrantTypes:             []string{"refresh_token"},
			AccessTokenTTLSeconds:  3600,
			RefreshTokenTTLSeconds: 7200,
			Status:                 "active",
		},
	}
	tokenRepo := &stubTokenRepository{}
	service := NewService(nil, clientRepo, nil, tokenRepo, &stubTokenCache{refreshRevoked: true}, &stubTokenPasswordVerifier{}, &stubSigner{}, "http://localhost:8080")

	_, err := service.Exchange(context.Background(), ExchangeInput{
		GrantType:    pkgoauth2.GrantTypeRefreshToken,
		ClientID:     "service-client",
		ClientSecret: "service-secret",
		RefreshToken: "revoked-refresh-token",
	})
	if err != ErrInvalidRefreshToken {
		t.Fatalf("Exchange() error = %v, want %v", err, ErrInvalidRefreshToken)
	}
}
