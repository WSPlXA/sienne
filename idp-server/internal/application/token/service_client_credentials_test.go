package token

import (
	"context"
	"errors"
	"testing"
	"time"

	clientdomain "idp-server/internal/domain/client"
	tokendomain "idp-server/internal/domain/token"
	pkgoauth2 "idp-server/pkg/oauth2"
)

type stubTokenClientRepository struct {
	model *clientdomain.Model
}

func (s *stubTokenClientRepository) FindByClientID(_ context.Context, clientID string) (*clientdomain.Model, error) {
	if s.model == nil || s.model.ClientID != clientID {
		return nil, nil
	}
	return s.model, nil
}

func (s *stubTokenClientRepository) CreateClient(_ context.Context, _ *clientdomain.Model) error {
	return nil
}

func (s *stubTokenClientRepository) RegisterRedirectURIs(_ context.Context, _ int64, _ []string) (int, error) {
	return 0, nil
}

func (s *stubTokenClientRepository) RegisterPostLogoutRedirectURIs(_ context.Context, _ int64, _ []string) (int, error) {
	return 0, nil
}

type stubTokenRepository struct {
	accessModel *tokendomain.AccessToken
}

func (s *stubTokenRepository) CreateAccessToken(_ context.Context, model *tokendomain.AccessToken) error {
	copyModel := *model
	s.accessModel = &copyModel
	return nil
}

func (s *stubTokenRepository) CreateRefreshToken(_ context.Context, _ *tokendomain.RefreshToken) error {
	return nil
}

func (s *stubTokenRepository) FindActiveAccessTokenBySHA256(_ context.Context, _ string) (*tokendomain.AccessToken, error) {
	return nil, nil
}

func (s *stubTokenRepository) FindActiveRefreshTokenBySHA256(_ context.Context, _ string) (*tokendomain.RefreshToken, error) {
	return nil, nil
}

func (s *stubTokenRepository) RotateRefreshToken(_ context.Context, _ string, _ time.Time, _ *tokendomain.RefreshToken) error {
	return nil
}

type stubTokenPasswordVerifier struct{}

func (s *stubTokenPasswordVerifier) HashPassword(password string) (string, error) {
	return password, nil
}

func (s *stubTokenPasswordVerifier) VerifyPassword(password, encodedHash string) error {
	if encodedHash != "hashed:service-secret" || password != "service-secret" {
		return errors.New("mismatch")
	}
	return nil
}

type stubSigner struct{}

func (s *stubSigner) Mint(claims map[string]any) (string, error) {
	return "signed-token", nil
}

func TestExchangeClientCredentials(t *testing.T) {
	clientRepo := &stubTokenClientRepository{
		model: &clientdomain.Model{
			ID:                    7,
			ClientID:              "service-client",
			ClientSecretHash:      "hashed:service-secret",
			GrantTypes:            []string{"client_credentials"},
			Scopes:                []string{"internal.api.read", "internal.api.write"},
			AccessTokenTTLSeconds: 3600,
			Status:                "active",
		},
	}
	tokenRepo := &stubTokenRepository{}
	service := NewService(nil, clientRepo, nil, tokenRepo, nil, &stubTokenPasswordVerifier{}, &stubSigner{}, "http://localhost:8080")

	result, err := service.Exchange(context.Background(), ExchangeInput{
		GrantType:    pkgoauth2.GrantTypeClientCredentials,
		ClientID:     "service-client",
		ClientSecret: "service-secret",
		Scopes:       []string{"internal.api.read"},
	})
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if result.AccessToken != "signed-token" {
		t.Fatalf("access token = %q", result.AccessToken)
	}
	if result.Scope != "internal.api.read" {
		t.Fatalf("scope = %q", result.Scope)
	}
	if tokenRepo.accessModel == nil {
		t.Fatal("CreateAccessToken() was not called")
	}
	if tokenRepo.accessModel.Subject != "service-client" {
		t.Fatalf("subject = %q", tokenRepo.accessModel.Subject)
	}
	if tokenRepo.accessModel.UserID != nil {
		t.Fatalf("user id = %v, want nil", tokenRepo.accessModel.UserID)
	}
}
