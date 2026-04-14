package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	tokendomain "idp-server/internal/domain/token"
	userdomain "idp-server/internal/domain/user"
	cacheport "idp-server/internal/ports/cache"
)

type stubOIDCUserRepository struct {
	user *userdomain.Model
}

func (s *stubOIDCUserRepository) Create(context.Context, *userdomain.Model) error { return nil }
func (s *stubOIDCUserRepository) FindByID(context.Context, int64) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubOIDCUserRepository) FindByUserUUID(context.Context, string) (*userdomain.Model, error) {
	return s.user, nil
}
func (s *stubOIDCUserRepository) FindByEmail(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubOIDCUserRepository) FindByUsername(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubOIDCUserRepository) ListByRoleCode(context.Context, string, int) ([]*userdomain.Model, error) {
	return nil, nil
}
func (s *stubOIDCUserRepository) CountByRoleCode(context.Context, string) (int64, error) {
	return 0, nil
}
func (s *stubOIDCUserRepository) UpdateRoleAndPrivilege(context.Context, int64, string, uint32, string) error {
	return nil
}
func (s *stubOIDCUserRepository) UnlockAccount(context.Context, int64, time.Time) error {
	return nil
}
func (s *stubOIDCUserRepository) IncrementFailedLogin(context.Context, int64) (int64, error) {
	return 0, nil
}
func (s *stubOIDCUserRepository) ResetFailedLogin(context.Context, int64, time.Time) error {
	return nil
}

type stubOIDCTokenRepository struct {
	accessToken *tokendomain.AccessToken
}

func (s *stubOIDCTokenRepository) CreateAccessToken(context.Context, *tokendomain.AccessToken) error {
	return nil
}
func (s *stubOIDCTokenRepository) CreateRefreshToken(context.Context, *tokendomain.RefreshToken) error {
	return nil
}
func (s *stubOIDCTokenRepository) FindActiveAccessTokenBySHA256(context.Context, string) (*tokendomain.AccessToken, error) {
	return s.accessToken, nil
}
func (s *stubOIDCTokenRepository) FindActiveRefreshTokenBySHA256(context.Context, string) (*tokendomain.RefreshToken, error) {
	return nil, nil
}
func (s *stubOIDCTokenRepository) RotateRefreshToken(context.Context, string, time.Time, *tokendomain.RefreshToken) error {
	return nil
}

type stubOIDCTokenCache struct {
	accessEntry *cacheport.AccessTokenCacheEntry
	revoked     bool
}

func (s *stubOIDCTokenCache) SaveAccessToken(context.Context, cacheport.AccessTokenCacheEntry, time.Duration) error {
	return nil
}
func (s *stubOIDCTokenCache) GetAccessToken(context.Context, string) (*cacheport.AccessTokenCacheEntry, error) {
	return s.accessEntry, nil
}
func (s *stubOIDCTokenCache) SaveRefreshToken(context.Context, cacheport.RefreshTokenCacheEntry, time.Duration) error {
	return nil
}
func (s *stubOIDCTokenCache) GetRefreshToken(context.Context, string) (*cacheport.RefreshTokenCacheEntry, error) {
	return nil, nil
}
func (s *stubOIDCTokenCache) CheckRefreshTokenReplay(context.Context, string, string) (*cacheport.RefreshTokenReplayResult, error) {
	return &cacheport.RefreshTokenReplayResult{Status: cacheport.RefreshTokenReplayNone}, nil
}
func (s *stubOIDCTokenCache) RotateRefreshToken(context.Context, string, cacheport.RefreshTokenCacheEntry, cacheport.TokenResponseCacheEntry, string, time.Duration, time.Duration) error {
	return nil
}
func (s *stubOIDCTokenCache) RevokeAccessToken(context.Context, string, time.Duration) error {
	return nil
}
func (s *stubOIDCTokenCache) RevokeRefreshToken(context.Context, string, time.Duration) error {
	return nil
}
func (s *stubOIDCTokenCache) IsAccessTokenRevoked(context.Context, string) (bool, error) {
	return s.revoked, nil
}
func (s *stubOIDCTokenCache) IsRefreshTokenRevoked(context.Context, string) (bool, error) {
	return false, nil
}

type stubOIDCValidator struct {
	claims map[string]any
	err    error
}

func (s *stubOIDCValidator) ParseAndValidate(string, ValidateOptions) (map[string]any, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.claims, nil
}

type stubJWKSProvider struct{}

func (s stubJWKSProvider) PublicJWKS() []JSONWebKey { return nil }

func TestIntrospectReturnsActiveTokenMetadata(t *testing.T) {
	now := time.Date(2026, 3, 25, 12, 0, 0, 0, time.UTC)
	service := NewService(
		&stubOIDCUserRepository{user: &userdomain.Model{
			UserUUID:  "user-42",
			Username:  "alice",
			UpdatedAt: now,
		}},
		nil,
		&stubOIDCTokenCache{accessEntry: &cacheport.AccessTokenCacheEntry{ExpiresAt: now.Add(5 * time.Minute)}},
		&stubOIDCValidator{claims: map[string]any{
			"iss": "http://localhost:8080",
			"sub": "user-42",
			"aud": []any{"api"},
			"exp": float64(now.Add(5 * time.Minute).Unix()),
			"iat": float64(now.Add(-1 * time.Minute).Unix()),
			"nbf": float64(now.Add(-1 * time.Minute).Unix()),
			"jti": "jti-123",
			"cid": "web-client",
			"scp": []any{"openid", "profile"},
		}},
		stubJWKSProvider{},
		"http://localhost:8080",
	)
	service.now = func() time.Time { return now }

	result, err := service.Introspect(context.Background(), IntrospectionInput{AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if !result.Active {
		t.Fatalf("active = false, want true")
	}
	if result.ClientID != "web-client" {
		t.Fatalf("client_id = %q, want web-client", result.ClientID)
	}
	if result.Scope != "openid profile" {
		t.Fatalf("scope = %q, want \"openid profile\"", result.Scope)
	}
	if result.Username != "alice" {
		t.Fatalf("username = %q, want alice", result.Username)
	}
}

func TestIntrospectReturnsInactiveForRevokedToken(t *testing.T) {
	service := NewService(
		nil,
		nil,
		&stubOIDCTokenCache{revoked: true},
		&stubOIDCValidator{},
		stubJWKSProvider{},
		"http://localhost:8080",
	)

	result, err := service.Introspect(context.Background(), IntrospectionInput{AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if result.Active {
		t.Fatalf("active = true, want false")
	}
}

func TestIntrospectReturnsInactiveForInvalidToken(t *testing.T) {
	service := NewService(
		nil,
		&stubOIDCTokenRepository{accessToken: &tokendomain.AccessToken{}},
		nil,
		&stubOIDCValidator{err: errors.New("invalid token")},
		stubJWKSProvider{},
		"http://localhost:8080",
	)

	result, err := service.Introspect(context.Background(), IntrospectionInput{AccessToken: "access-token"})
	if err != nil {
		t.Fatalf("Introspect() error = %v", err)
	}
	if result.Active {
		t.Fatalf("active = true, want false")
	}
}
