package token

import (
	"context"
	"testing"
	"time"

	clientdomain "idp-server/internal/domain/client"
	tokendomain "idp-server/internal/domain/token"
	userdomain "idp-server/internal/domain/user"
	pkgoauth2 "idp-server/pkg/oauth2"
)

type stubTokenUserRepository struct {
	model *userdomain.Model
}

func (s *stubTokenUserRepository) Create(context.Context, *userdomain.Model) error { return nil }
func (s *stubTokenUserRepository) FindByID(context.Context, int64) (*userdomain.Model, error) {
	return s.model, nil
}
func (s *stubTokenUserRepository) FindByUserUUID(context.Context, string) (*userdomain.Model, error) {
	return s.model, nil
}
func (s *stubTokenUserRepository) FindByEmail(context.Context, string) (*userdomain.Model, error) {
	return s.model, nil
}
func (s *stubTokenUserRepository) FindByUsername(_ context.Context, username string) (*userdomain.Model, error) {
	if s.model == nil || s.model.Username != username {
		return nil, nil
	}
	return s.model, nil
}
func (s *stubTokenUserRepository) ListByRoleCode(context.Context, string, int) ([]*userdomain.Model, error) {
	return nil, nil
}
func (s *stubTokenUserRepository) CountByRoleCode(context.Context, string) (int64, error) {
	return 0, nil
}
func (s *stubTokenUserRepository) UpdateRoleAndPrivilege(context.Context, int64, string, uint32, string) error {
	return nil
}
func (s *stubTokenUserRepository) IncrementFailedLogin(context.Context, int64) (int64, error) {
	return 0, nil
}
func (s *stubTokenUserRepository) ResetFailedLogin(context.Context, int64, time.Time) error {
	return nil
}

type passwordGrantTokenRepository struct {
	access  *tokendomain.AccessToken
	refresh *tokendomain.RefreshToken
}

func (s *passwordGrantTokenRepository) CreateAccessToken(_ context.Context, model *tokendomain.AccessToken) error {
	copyModel := *model
	s.access = &copyModel
	return nil
}
func (s *passwordGrantTokenRepository) CreateRefreshToken(_ context.Context, model *tokendomain.RefreshToken) error {
	copyModel := *model
	s.refresh = &copyModel
	return nil
}
func (s *passwordGrantTokenRepository) FindActiveAccessTokenBySHA256(context.Context, string) (*tokendomain.AccessToken, error) {
	return nil, nil
}
func (s *passwordGrantTokenRepository) FindActiveRefreshTokenBySHA256(context.Context, string) (*tokendomain.RefreshToken, error) {
	return nil, nil
}
func (s *passwordGrantTokenRepository) RotateRefreshToken(context.Context, string, time.Time, *tokendomain.RefreshToken) error {
	return nil
}

func TestExchangePasswordGrant(t *testing.T) {
	clientRepo := &stubTokenClientRepository{
		model: &clientdomain.Model{
			ID:                     9,
			ClientID:               "legacy-client",
			ClientSecretHash:       "hashed:service-secret",
			GrantTypes:             []string{"password", "refresh_token"},
			Scopes:                 []string{"openid", "profile", "offline_access"},
			AccessTokenTTLSeconds:  3600,
			RefreshTokenTTLSeconds: 7200,
			Status:                 "active",
		},
	}
	userRepo := &stubTokenUserRepository{
		model: &userdomain.Model{
			ID:           42,
			UserUUID:     "user-42",
			Username:     "alice",
			PasswordHash: "hashed:service-secret",
			Status:       "active",
		},
	}
	tokenRepo := &passwordGrantTokenRepository{}
	service := NewService(nil, clientRepo, userRepo, tokenRepo, nil, nil, &stubTokenPasswordVerifier{}, &stubSigner{}, "http://localhost:8080")

	result, err := service.Exchange(context.Background(), ExchangeInput{
		GrantType:    pkgoauth2.GrantTypePassword,
		ClientID:     "legacy-client",
		ClientSecret: "service-secret",
		Username:     "alice",
		Password:     "service-secret",
		Scopes:       []string{"openid", "offline_access"},
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if result.AccessToken != "signed-token" {
		t.Fatalf("access token = %q", result.AccessToken)
	}
	if result.RefreshToken == "" {
		t.Fatal("expected refresh token to be issued")
	}
	if tokenRepo.access == nil || tokenRepo.refresh == nil {
		t.Fatal("expected access and refresh tokens to be persisted")
	}
}
