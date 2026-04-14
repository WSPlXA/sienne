package session

import (
	"context"
	"testing"
	"time"

	sessiondomain "idp-server/internal/domain/session"
	tokendomain "idp-server/internal/domain/token"
	cacheport "idp-server/internal/ports/cache"
)

type stubSessionRepository struct {
	model           *sessiondomain.Model
	activeSessions  []*sessiondomain.Model
	loggedOutAt     time.Time
	logoutCalls     int
	logoutAllCalls  int
	findSessionID   string
	logoutAllUserID int64
}

func (s *stubSessionRepository) Create(context.Context, *sessiondomain.Model) error {
	return nil
}

func (s *stubSessionRepository) FindBySessionID(_ context.Context, sessionID string) (*sessiondomain.Model, error) {
	s.findSessionID = sessionID
	return s.model, nil
}

func (s *stubSessionRepository) ListActiveByUserID(context.Context, int64) ([]*sessiondomain.Model, error) {
	return s.activeSessions, nil
}

func (s *stubSessionRepository) LogoutBySessionID(_ context.Context, _ string, loggedOutAt time.Time) error {
	s.loggedOutAt = loggedOutAt
	s.logoutCalls++
	return nil
}

func (s *stubSessionRepository) LogoutAllByUserID(_ context.Context, userID int64, loggedOutAt time.Time) error {
	s.logoutAllCalls++
	s.logoutAllUserID = userID
	s.loggedOutAt = loggedOutAt
	return nil
}

type stubSessionCache struct {
	deletedSessionID string
	deletedSessions  []string
	userSessionIDs   []string
}

func (s *stubSessionCache) Save(context.Context, cacheport.SessionCacheEntry, time.Duration) error {
	return nil
}

func (s *stubSessionCache) Get(context.Context, string) (*cacheport.SessionCacheEntry, error) {
	return nil, nil
}

func (s *stubSessionCache) Delete(_ context.Context, sessionID string) error {
	s.deletedSessionID = sessionID
	s.deletedSessions = append(s.deletedSessions, sessionID)
	return nil
}

func (s *stubSessionCache) AddUserSessionIndex(context.Context, string, string, time.Duration) error {
	return nil
}

func (s *stubSessionCache) ListUserSessionIDs(context.Context, string) ([]string, error) {
	return append([]string(nil), s.userSessionIDs...), nil
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
	service := NewService(repo, cache, nil, nil)
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

type stubTokenRevoker struct {
	accessTokens         []*tokendomain.AccessToken
	refreshTokens        []*tokendomain.RefreshToken
	revokedAccessUserID  int64
	revokedRefreshUserID int64
}

func (s *stubTokenRevoker) ListActiveAccessTokensByUserID(context.Context, int64) ([]*tokendomain.AccessToken, error) {
	return s.accessTokens, nil
}

func (s *stubTokenRevoker) ListActiveRefreshTokensByUserID(context.Context, int64) ([]*tokendomain.RefreshToken, error) {
	return s.refreshTokens, nil
}

func (s *stubTokenRevoker) RevokeAccessTokensByUserID(_ context.Context, userID int64, _ time.Time) error {
	s.revokedAccessUserID = userID
	return nil
}

func (s *stubTokenRevoker) RevokeRefreshTokensByUserID(_ context.Context, userID int64, _ time.Time) error {
	s.revokedRefreshUserID = userID
	return nil
}

type stubTokenCache struct {
	revokedAccess  []string
	revokedRefresh []string
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
	return &cacheport.RefreshTokenReplayResult{Status: cacheport.RefreshTokenReplayNone}, nil
}

func (s *stubTokenCache) RotateRefreshToken(context.Context, string, cacheport.RefreshTokenCacheEntry, cacheport.TokenResponseCacheEntry, string, time.Duration, time.Duration) error {
	return nil
}

func (s *stubTokenCache) RevokeAccessToken(_ context.Context, tokenSHA256 string, _ time.Duration) error {
	s.revokedAccess = append(s.revokedAccess, tokenSHA256)
	return nil
}

func (s *stubTokenCache) RevokeRefreshToken(_ context.Context, tokenSHA256 string, _ time.Duration) error {
	s.revokedRefresh = append(s.revokedRefresh, tokenSHA256)
	return nil
}

func (s *stubTokenCache) IsAccessTokenRevoked(context.Context, string) (bool, error) {
	return false, nil
}

func (s *stubTokenCache) IsRefreshTokenRevoked(context.Context, string) (bool, error) {
	return false, nil
}

func TestLogoutAllRevokesSessionsAndTokens(t *testing.T) {
	now := time.Date(2026, 4, 7, 12, 0, 0, 0, time.UTC)
	repo := &stubSessionRepository{
		model: &sessiondomain.Model{
			SessionID: "session-current",
			UserID:    42,
		},
		activeSessions: []*sessiondomain.Model{
			{SessionID: "session-current", UserID: 42},
			{SessionID: "session-other", UserID: 42},
		},
	}
	cache := &stubSessionCache{
		userSessionIDs: []string{"session-other", "session-mobile"},
	}
	tokenRepo := &stubTokenRevoker{
		accessTokens: []*tokendomain.AccessToken{
			{TokenSHA256: "access-1", ExpiresAt: now.Add(30 * time.Minute)},
		},
		refreshTokens: []*tokendomain.RefreshToken{
			{TokenSHA256: "refresh-1", ExpiresAt: now.Add(24 * time.Hour)},
		},
	}
	tokenCache := &stubTokenCache{}
	service := NewService(repo, cache, tokenRepo, tokenCache)
	service.now = func() time.Time { return now }

	result, err := service.LogoutAll(context.Background(), LogoutAllInput{SessionID: "session-current"})
	if err != nil {
		t.Fatalf("LogoutAll() error = %v", err)
	}
	if repo.logoutAllCalls != 1 {
		t.Fatalf("logout all calls = %d, want 1", repo.logoutAllCalls)
	}
	if repo.logoutAllUserID != 42 {
		t.Fatalf("logout all user id = %d, want 42", repo.logoutAllUserID)
	}
	if len(cache.deletedSessions) != 3 {
		t.Fatalf("deleted sessions = %v, want 3 unique sessions", cache.deletedSessions)
	}
	if tokenRepo.revokedAccessUserID != 42 || tokenRepo.revokedRefreshUserID != 42 {
		t.Fatalf("token revoke user ids = %d/%d, want 42/42", tokenRepo.revokedAccessUserID, tokenRepo.revokedRefreshUserID)
	}
	if len(tokenCache.revokedAccess) != 1 || tokenCache.revokedAccess[0] != "access-1" {
		t.Fatalf("revoked access = %v", tokenCache.revokedAccess)
	}
	if len(tokenCache.revokedRefresh) != 1 || tokenCache.revokedRefresh[0] != "refresh-1" {
		t.Fatalf("revoked refresh = %v", tokenCache.revokedRefresh)
	}
	if result.RevokedSessionCount != 3 {
		t.Fatalf("revoked session count = %d, want 3", result.RevokedSessionCount)
	}
}
