package token

import (
	"context"
	"testing"
	"time"

	clientdomain "idp-server/internal/domain/client"
	tokendomain "idp-server/internal/domain/token"
	userdomain "idp-server/internal/domain/user"
	cacheport "idp-server/internal/ports/cache"
	pkgoauth2 "idp-server/pkg/oauth2"
)

type stubTokenCache struct {
	accessRevoked   bool
	refreshRevoked  bool
	replayResult    *cacheport.RefreshTokenReplayResult
	rotateErr       error
	rotatedResponse cacheport.TokenResponseCacheEntry
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

func (s *stubTokenCache) CheckRefreshTokenReplay(context.Context, string, string) (*cacheport.RefreshTokenReplayResult, error) {
	if s.replayResult == nil {
		return &cacheport.RefreshTokenReplayResult{Status: cacheport.RefreshTokenReplayNone}, nil
	}
	return s.replayResult, nil
}

func (s *stubTokenCache) RotateRefreshToken(_ context.Context, _ string, _ cacheport.RefreshTokenCacheEntry, response cacheport.TokenResponseCacheEntry, _ string, _ time.Duration, _ time.Duration) error {
	s.rotatedResponse = response
	return s.rotateErr
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

type refreshGrantTokenRepository struct {
	refresh   *tokendomain.RefreshToken
	rotateErr error
}

func (s *refreshGrantTokenRepository) CreateAccessToken(context.Context, *tokendomain.AccessToken) error {
	return nil
}
func (s *refreshGrantTokenRepository) CreateRefreshToken(context.Context, *tokendomain.RefreshToken) error {
	return nil
}
func (s *refreshGrantTokenRepository) FindActiveAccessTokenBySHA256(context.Context, string) (*tokendomain.AccessToken, error) {
	return nil, nil
}
func (s *refreshGrantTokenRepository) FindActiveRefreshTokenBySHA256(context.Context, string) (*tokendomain.RefreshToken, error) {
	return s.refresh, nil
}
func (s *refreshGrantTokenRepository) RotateRefreshToken(context.Context, string, time.Time, *tokendomain.RefreshToken) error {
	return s.rotateErr
}

func TestExchangeRefreshTokenRejectsCompromisedReplayFromCache(t *testing.T) {
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
	service := NewService(nil, clientRepo, nil, tokenRepo, &stubTokenCache{replayResult: &cacheport.RefreshTokenReplayResult{Status: cacheport.RefreshTokenReplayRejected}}, nil, &stubTokenPasswordVerifier{}, &stubSigner{}, "http://localhost:8080")

	_, err := service.Exchange(context.Background(), ExchangeInput{
		GrantType:         pkgoauth2.GrantTypeRefreshToken,
		ClientID:          "service-client",
		ClientSecret:      "service-secret",
		RefreshToken:      "revoked-refresh-token",
		ReplayFingerprint: "fp-1",
	})
	if err != ErrInvalidRefreshToken {
		t.Fatalf("Exchange() error = %v, want %v", err, ErrInvalidRefreshToken)
	}
}

func TestExchangeRefreshTokenReturnsGraceReplay(t *testing.T) {
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
	cache := &stubTokenCache{
		replayResult: &cacheport.RefreshTokenReplayResult{
			Status: cacheport.RefreshTokenReplayGrace,
			Response: &cacheport.TokenResponseCacheEntry{
				AccessToken:  "cached-access",
				TokenType:    "Bearer",
				ExpiresIn:    3599,
				RefreshToken: "cached-refresh",
				Scope:        "openid profile",
			},
		},
	}
	service := NewService(nil, clientRepo, nil, &stubTokenRepository{}, cache, nil, &stubTokenPasswordVerifier{}, &stubSigner{}, "http://localhost:8080")

	result, err := service.Exchange(context.Background(), ExchangeInput{
		GrantType:         pkgoauth2.GrantTypeRefreshToken,
		ClientID:          "service-client",
		ClientSecret:      "service-secret",
		RefreshToken:      "retry-token",
		ReplayFingerprint: "fp-1",
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if result.AccessToken != "cached-access" || result.RefreshToken != "cached-refresh" {
		t.Fatalf("grace replay result = %#v", result)
	}
}

func TestExchangeRefreshTokenCachesFirstSuccessfulRotation(t *testing.T) {
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
	userID := int64(42)
	tokenRepo := &refreshGrantTokenRepository{
		refresh: &tokendomain.RefreshToken{
			ID:          100,
			TokenSHA256: "old-sha",
			ClientID:    7,
			UserID:      &userID,
			Subject:     "user-42",
			ScopesJSON:  "[\"openid\"]",
			IssuedAt:    time.Now().Add(-time.Hour),
			ExpiresAt:   time.Now().Add(time.Hour),
		},
	}
	userRepo := &stubTokenUserRepository{
		model: &userdomain.Model{ID: 42, UserUUID: "user-42", Username: "alice", Status: "active"},
	}
	cache := &stubTokenCache{}
	service := NewService(nil, clientRepo, userRepo, tokenRepo, cache, nil, &stubTokenPasswordVerifier{}, &stubSigner{}, "http://localhost:8080")

	result, err := service.Exchange(context.Background(), ExchangeInput{
		GrantType:         pkgoauth2.GrantTypeRefreshToken,
		ClientID:          "service-client",
		ClientSecret:      "service-secret",
		RefreshToken:      "old-token",
		ReplayFingerprint: "fp-1",
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if result.RefreshToken == "" {
		t.Fatal("expected rotated refresh token")
	}
	if cache.rotatedResponse.RefreshToken == "" || cache.rotatedResponse.AccessToken == "" {
		t.Fatalf("cached rotated response = %#v", cache.rotatedResponse)
	}
}
