package session

import (
	"context"
	"testing"
	"time"

	sessiondomain "idp-server/internal/domain/session"
	cacheport "idp-server/internal/ports/cache"
)

type stubSessionRepository struct {
	model           *sessiondomain.Model
	loggedOutAt     time.Time
	logoutCalls     int
	findSessionID   string
}

func (s *stubSessionRepository) Create(context.Context, *sessiondomain.Model) error {
	return nil
}

func (s *stubSessionRepository) FindBySessionID(_ context.Context, sessionID string) (*sessiondomain.Model, error) {
	s.findSessionID = sessionID
	return s.model, nil
}

func (s *stubSessionRepository) ListActiveByUserID(context.Context, int64) ([]*sessiondomain.Model, error) {
	return nil, nil
}

func (s *stubSessionRepository) LogoutBySessionID(_ context.Context, _ string, loggedOutAt time.Time) error {
	s.loggedOutAt = loggedOutAt
	s.logoutCalls++
	return nil
}

func (s *stubSessionRepository) LogoutAllByUserID(context.Context, int64, time.Time) error {
	return nil
}

type stubSessionCache struct {
	deletedSessionID string
}

func (s *stubSessionCache) Save(context.Context, cacheport.SessionCacheEntry, time.Duration) error {
	return nil
}

func (s *stubSessionCache) Get(context.Context, string) (*cacheport.SessionCacheEntry, error) {
	return nil, nil
}

func (s *stubSessionCache) Delete(_ context.Context, sessionID string) error {
	s.deletedSessionID = sessionID
	return nil
}

func (s *stubSessionCache) AddUserSessionIndex(context.Context, string, string, time.Duration) error {
	return nil
}

func (s *stubSessionCache) ListUserSessionIDs(context.Context, string) ([]string, error) {
	return nil, nil
}

func (s *stubSessionCache) RemoveUserSessionIndex(context.Context, string, string) error {
	return nil
}

func TestLogoutMarksSessionAndClearsCache(t *testing.T) {
	now := time.Date(2026, 3, 24, 12, 0, 0, 0, time.UTC)
	repo := &stubSessionRepository{
		model: &sessiondomain.Model{
			SessionID: "session-123",
			UserID:    42,
		},
	}
	cache := &stubSessionCache{}
	service := NewService(repo, cache)
	service.now = func() time.Time { return now }

	result, err := service.Logout(context.Background(), LogoutInput{SessionID: "session-123"})
	if err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
	if repo.logoutCalls != 1 {
		t.Fatalf("logout calls = %d, want 1", repo.logoutCalls)
	}
	if cache.deletedSessionID != "session-123" {
		t.Fatalf("deleted session = %q, want session-123", cache.deletedSessionID)
	}
	if result.UserID != "42" {
		t.Fatalf("user id = %q, want 42", result.UserID)
	}
}
