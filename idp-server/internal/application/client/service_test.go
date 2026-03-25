package client

import (
	"context"
	"testing"

	clientdomain "idp-server/internal/domain/client"
)

type stubClientRepository struct {
	model                          *clientdomain.Model
	insertedCount                  int
	receivedClientDBID             int64
	receivedRedirectURIs           []string
	receivedPostLogoutRedirectURIs []string
	createdModel                   *clientdomain.Model
}

func (s *stubClientRepository) FindByClientID(_ context.Context, clientID string) (*clientdomain.Model, error) {
	if s.model == nil || s.model.ClientID != clientID {
		return nil, nil
	}
	return s.model, nil
}

func (s *stubClientRepository) CreateClient(_ context.Context, model *clientdomain.Model) error {
	copyModel := *model
	copyModel.GrantTypes = append([]string(nil), model.GrantTypes...)
	copyModel.AuthMethods = append([]string(nil), model.AuthMethods...)
	copyModel.Scopes = append([]string(nil), model.Scopes...)
	copyModel.RedirectURIs = append([]string(nil), model.RedirectURIs...)
	copyModel.PostLogoutRedirectURIs = append([]string(nil), model.PostLogoutRedirectURIs...)
	s.createdModel = &copyModel
	return nil
}

func (s *stubClientRepository) RegisterRedirectURIs(_ context.Context, clientDBID int64, redirectURIs []string) (int, error) {
	s.receivedClientDBID = clientDBID
	s.receivedRedirectURIs = append([]string(nil), redirectURIs...)
	return s.insertedCount, nil
}

func (s *stubClientRepository) RegisterPostLogoutRedirectURIs(_ context.Context, clientDBID int64, redirectURIs []string) (int, error) {
	s.receivedClientDBID = clientDBID
	s.receivedPostLogoutRedirectURIs = append([]string(nil), redirectURIs...)
	return s.insertedCount, nil
}

type stubPasswordVerifier struct {
	lastPassword string
}

func (s *stubPasswordVerifier) HashPassword(password string) (string, error) {
	s.lastPassword = password
	return "hashed:" + password, nil
}

func (s *stubPasswordVerifier) VerifyPassword(password, encodedHash string) error {
	return nil
}

func TestCreateClientBuildsIntegratedAuthorizationCodeClient(t *testing.T) {
	repo := &stubClientRepository{}
	passwords := &stubPasswordVerifier{}
	service := NewService(repo, passwords)

	result, err := service.CreateClient(context.Background(), CreateClientInput{
		ClientID:               "demo-web-client",
		ClientName:             "Demo Web Client",
		ClientSecret:           "super-secret-1",
		GrantTypes:             []string{"authorization_code", "refresh_token"},
		Scopes:                 []string{"openid", "profile", "offline_access"},
		RedirectURIs:           []string{"https://app.example.com/callback"},
		AccessTokenTTLSeconds:  7200,
		RefreshTokenTTLSeconds: 86400,
		IDTokenTTLSeconds:      7200,
	})
	if err != nil {
		t.Fatalf("CreateClient() error = %v", err)
	}
	if repo.createdModel == nil {
		t.Fatal("CreateClient() did not persist a model")
	}
	if repo.createdModel.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Fatalf("auth method = %q", repo.createdModel.TokenEndpointAuthMethod)
	}
	if repo.createdModel.ClientSecretHash != "hashed:super-secret-1" {
		t.Fatalf("secret hash = %q", repo.createdModel.ClientSecretHash)
	}
	if len(repo.createdModel.RedirectURIs) != 1 || repo.createdModel.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Fatalf("redirect uris = %#v", repo.createdModel.RedirectURIs)
	}
	if passwords.lastPassword != "super-secret-1" {
		t.Fatalf("last hashed password = %q", passwords.lastPassword)
	}
	if result.ClientType != "confidential" {
		t.Fatalf("client type = %q", result.ClientType)
	}
}

func TestCreateClientRejectsPublicClientWithoutPKCE(t *testing.T) {
	repo := &stubClientRepository{}
	service := NewService(repo, &stubPasswordVerifier{})
	requirePKCE := false

	_, err := service.CreateClient(context.Background(), CreateClientInput{
		ClientID:     "demo-public-client",
		ClientName:   "Demo Public Client",
		ClientType:   "public",
		RequirePKCE:  &requirePKCE,
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		RedirectURIs: []string{"myapp://callback"},
	})
	if err != ErrInvalidClientConfig {
		t.Fatalf("CreateClient() error = %v, want %v", err, ErrInvalidClientConfig)
	}
}

func TestRegisterRedirectURIsNormalizesAndDeduplicates(t *testing.T) {
	repo := &stubClientRepository{
		model: &clientdomain.Model{
			ID:         42,
			ClientID:   "web-client",
			ClientName: "Web Client",
		},
		insertedCount: 1,
	}
	service := NewService(repo, &stubPasswordVerifier{})

	result, err := service.RegisterRedirectURIs(context.Background(), RegisterRedirectURIsInput{
		ClientID: " web-client ",
		RedirectURIs: []string{
			" https://app.example.com/callback ",
			"https://app.example.com/callback",
			"https://app.example.com/alt",
		},
	})
	if err != nil {
		t.Fatalf("RegisterRedirectURIs() error = %v", err)
	}

	if repo.receivedClientDBID != 42 {
		t.Fatalf("received client DB id = %d, want 42", repo.receivedClientDBID)
	}
	if len(repo.receivedRedirectURIs) != 2 {
		t.Fatalf("received redirect uri count = %d, want 2", len(repo.receivedRedirectURIs))
	}
	if repo.receivedRedirectURIs[0] != "https://app.example.com/callback" {
		t.Fatalf("first redirect uri = %q", repo.receivedRedirectURIs[0])
	}
	if repo.receivedRedirectURIs[1] != "https://app.example.com/alt" {
		t.Fatalf("second redirect uri = %q", repo.receivedRedirectURIs[1])
	}
	if result.RegisteredCount != 1 {
		t.Fatalf("registered count = %d, want 1", result.RegisteredCount)
	}
	if result.SkippedCount != 1 {
		t.Fatalf("skipped count = %d, want 1", result.SkippedCount)
	}
}

func TestRegisterRedirectURIsRejectsFragments(t *testing.T) {
	service := NewService(&stubClientRepository{
		model: &clientdomain.Model{ID: 1, ClientID: "web-client"},
	}, &stubPasswordVerifier{})

	_, err := service.RegisterRedirectURIs(context.Background(), RegisterRedirectURIsInput{
		ClientID:     "web-client",
		RedirectURIs: []string{"https://app.example.com/callback#fragment"},
	})
	if err != ErrInvalidRedirectURI {
		t.Fatalf("RegisterRedirectURIs() error = %v, want %v", err, ErrInvalidRedirectURI)
	}
}

func TestRegisterRedirectURIsReturnsNotFoundWhenClientMissing(t *testing.T) {
	service := NewService(&stubClientRepository{}, &stubPasswordVerifier{})

	_, err := service.RegisterRedirectURIs(context.Background(), RegisterRedirectURIsInput{
		ClientID:     "missing-client",
		RedirectURIs: []string{"https://app.example.com/callback"},
	})
	if err != ErrClientNotFound {
		t.Fatalf("RegisterRedirectURIs() error = %v, want %v", err, ErrClientNotFound)
	}
}
