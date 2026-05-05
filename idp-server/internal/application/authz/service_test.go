package authz

import (
	"context"
	"testing"
	"time"

	authorizationdomain "idp-server/internal/domain/authorization"
	clientdomain "idp-server/internal/domain/client"
	sessiondomain "idp-server/internal/domain/session"
	cacheport "idp-server/internal/ports/cache"
)

type stubAuthzClientRepository struct {
	client *clientdomain.Model
}

func (s *stubAuthzClientRepository) FindByClientID(context.Context, string) (*clientdomain.Model, error) {
	return s.client, nil
}

func (s *stubAuthzClientRepository) HasPostLogoutRedirectURI(context.Context, int64, string) (bool, error) {
	return false, nil
}

func (s *stubAuthzClientRepository) CreateClient(context.Context, *clientdomain.Model) error {
	return nil
}

func (s *stubAuthzClientRepository) RegisterRedirectURIs(context.Context, int64, []string) (int, error) {
	return 0, nil
}

func (s *stubAuthzClientRepository) RegisterPostLogoutRedirectURIs(context.Context, int64, []string) (int, error) {
	return 0, nil
}

type stubAuthzSessionRepository struct {
	findCalls int
}

func (s *stubAuthzSessionRepository) Create(context.Context, *sessiondomain.Model) error {
	return nil
}

func (s *stubAuthzSessionRepository) FindBySessionID(context.Context, string) (*sessiondomain.Model, error) {
	s.findCalls++
	return nil, nil
}

func (s *stubAuthzSessionRepository) ListActiveByUserID(context.Context, int64) ([]*sessiondomain.Model, error) {
	return nil, nil
}

func (s *stubAuthzSessionRepository) LogoutBySessionID(context.Context, string, time.Time) error {
	return nil
}

func (s *stubAuthzSessionRepository) LogoutAllByUserID(context.Context, int64, time.Time) error {
	return nil
}

type stubAuthzSessionCache struct {
	entry *cacheport.SessionCacheEntry
}

func (s *stubAuthzSessionCache) Save(context.Context, cacheport.SessionCacheEntry, time.Duration) error {
	return nil
}

func (s *stubAuthzSessionCache) Get(context.Context, string) (*cacheport.SessionCacheEntry, error) {
	return s.entry, nil
}

func (s *stubAuthzSessionCache) Delete(context.Context, string) error {
	return nil
}

func (s *stubAuthzSessionCache) AddUserSessionIndex(context.Context, string, string, time.Duration) error {
	return nil
}

func (s *stubAuthzSessionCache) ListUserSessionIDs(context.Context, string) ([]string, error) {
	return nil, nil
}

func (s *stubAuthzSessionCache) RemoveUserSessionIndex(context.Context, string, string) error {
	return nil
}

type stubAuthzCodeRepository struct {
	created *authorizationdomain.Model
}

func (s *stubAuthzCodeRepository) Create(_ context.Context, model *authorizationdomain.Model) error {
	copyModel := *model
	s.created = &copyModel
	return nil
}

func (s *stubAuthzCodeRepository) ConsumeByCode(context.Context, string, time.Time) (*authorizationdomain.Model, error) {
	return nil, nil
}

func TestAuthorizeUsesSessionCacheBeforeDatabase(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	sessionRepo := &stubAuthzSessionRepository{}
	codeRepo := &stubAuthzCodeRepository{}
	service := NewService(
		&stubAuthzClientRepository{client: &clientdomain.Model{
			ID:           7,
			ClientID:     "web-client",
			Status:       "active",
			GrantTypes:   []string{"authorization_code"},
			RedirectURIs: []string{"http://localhost:3060/callback"},
			Scopes:       []string{"openid", "profile"},
		}},
		sessionRepo,
		&stubAuthzSessionCache{entry: &cacheport.SessionCacheEntry{
			SessionID:       "session-123",
			UserID:          "42",
			Subject:         "user-42",
			AuthenticatedAt: now.Add(-time.Minute),
			ExpiresAt:       now.Add(time.Hour),
			Status:          "active",
			StateMask:       cacheport.SessionStateActive,
		}},
		codeRepo,
		nil,
		10*time.Minute,
	)
	service.now = func() time.Time { return now }
	service.codeMaker = func() string { return "code-123" }

	result, err := service.Authorize(context.Background(), &AuthorizationCommand{
		ClientID:            "web-client",
		ResponseType:        "code",
		RedirectURI:         "http://localhost:3060/callback",
		Scope:               []string{"openid"},
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "plain",
		SessionID:           "session-123",
	})
	if err != nil {
		t.Fatalf("Authorize returned error: %v", err)
	}
	if result == nil || result.Code != "code-123" {
		t.Fatalf("Authorize result = %#v, want code-123", result)
	}
	if sessionRepo.findCalls != 0 {
		t.Fatalf("FindBySessionID calls = %d, want 0", sessionRepo.findCalls)
	}
	if codeRepo.created == nil || codeRepo.created.UserID != 42 {
		t.Fatalf("created code user id = %#v, want 42", codeRepo.created)
	}
	if codeRepo.created.SessionDBID != nil {
		t.Fatalf("created code session db id = %v, want nil for cache-only session", *codeRepo.created.SessionDBID)
	}
}
