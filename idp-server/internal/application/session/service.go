package session

import (
	"context"
	"strconv"
	"strings"
	"time"

	sessiondomain "idp-server/internal/domain/session"
	tokendomain "idp-server/internal/domain/token"
	"idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
)

type Manager interface {
	Logout(ctx context.Context, input LogoutInput) (*LogoutResult, error)
	LogoutAll(ctx context.Context, input LogoutAllInput) (*LogoutAllResult, error)
	AdminLogoutUser(ctx context.Context, input AdminLogoutUserInput) (*LogoutAllResult, error)
}

type tokenRevoker interface {
	ListActiveAccessTokensByUserID(ctx context.Context, userID int64) ([]*tokendomain.AccessToken, error)
	ListActiveRefreshTokensByUserID(ctx context.Context, userID int64) ([]*tokendomain.RefreshToken, error)
	RevokeAccessTokensByUserID(ctx context.Context, userID int64, revokedAt time.Time) error
	RevokeRefreshTokensByUserID(ctx context.Context, userID int64, revokedAt time.Time) error
}

type Service struct {
	sessions     repository.SessionRepository
	sessionCache cache.SessionCacheRepository
	tokens       tokenRevoker
	tokenCache   cache.TokenCacheRepository
	now          func() time.Time
}

func NewService(
	sessions repository.SessionRepository,
	sessionCache cache.SessionCacheRepository,
	tokens tokenRevoker,
	tokenCache cache.TokenCacheRepository,
) *Service {
	return &Service{
		sessions:     sessions,
		sessionCache: sessionCache,
		tokens:       tokens,
		tokenCache:   tokenCache,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (s *Service) Logout(ctx context.Context, input LogoutInput) (*LogoutResult, error) {
	sessionID := strings.TrimSpace(input.SessionID)
	if sessionID == "" {
		return &LogoutResult{}, nil
	}

	sessionModel, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if sessionModel == nil {
		if s.sessionCache != nil {
			if err := s.sessionCache.Delete(ctx, sessionID); err != nil {
				return nil, err
			}
		}
		return &LogoutResult{}, nil
	}

	if sessionModel.LoggedOutAt == nil {
		if err := s.sessions.LogoutBySessionID(ctx, sessionID, s.now()); err != nil {
			return nil, err
		}
	}

	if s.sessionCache != nil {
		if err := s.sessionCache.Delete(ctx, sessionID); err != nil {
			return nil, err
		}
	}

	return &LogoutResult{
		SessionID: sessionID,
		UserID:    strconv.FormatInt(sessionModel.UserID, 10),
	}, nil
}

func (s *Service) LogoutAll(ctx context.Context, input LogoutAllInput) (*LogoutAllResult, error) {
	sessionID := strings.TrimSpace(input.SessionID)
	if sessionID == "" {
		return &LogoutAllResult{}, nil
	}

	currentSession, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if currentSession == nil {
		if s.sessionCache != nil {
			if err := s.sessionCache.Delete(ctx, sessionID); err != nil {
				return nil, err
			}
		}
		return &LogoutAllResult{SessionID: sessionID}, nil
	}
	return s.logoutUser(ctx, currentSession.UserID, sessionID)
}

func (s *Service) AdminLogoutUser(ctx context.Context, input AdminLogoutUserInput) (*LogoutAllResult, error) {
	if input.UserID <= 0 {
		return &LogoutAllResult{}, nil
	}
	return s.logoutUser(ctx, input.UserID, "")
}

func (s *Service) collectUserSessionIDs(ctx context.Context, userID int64, activeSessions []*sessiondomain.Model) ([]string, error) {
	seen := make(map[string]struct{})
	ids := make([]string, 0, len(activeSessions))

	for _, sessionModel := range activeSessions {
		if sessionModel == nil {
			continue
		}
		sessionID := strings.TrimSpace(sessionModel.SessionID)
		if sessionID == "" {
			continue
		}
		if _, ok := seen[sessionID]; ok {
			continue
		}
		seen[sessionID] = struct{}{}
		ids = append(ids, sessionID)
	}

	if s.sessionCache != nil {
		cachedIDs, err := s.sessionCache.ListUserSessionIDs(ctx, strconv.FormatInt(userID, 10))
		if err != nil {
			return nil, err
		}
		for _, cachedID := range cachedIDs {
			cachedID = strings.TrimSpace(cachedID)
			if cachedID == "" {
				continue
			}
			if _, ok := seen[cachedID]; ok {
				continue
			}
			seen[cachedID] = struct{}{}
			ids = append(ids, cachedID)
		}
	}

	return ids, nil
}

func (s *Service) logoutUser(ctx context.Context, userID int64, sessionID string) (*LogoutAllResult, error) {
	now := s.now()
	activeSessions, err := s.sessions.ListActiveByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if err := s.sessions.LogoutAllByUserID(ctx, userID, now); err != nil {
		return nil, err
	}

	sessionIDs, err := s.collectUserSessionIDs(ctx, userID, activeSessions)
	if err != nil {
		return nil, err
	}
	for _, candidate := range sessionIDs {
		if candidate == "" || s.sessionCache == nil {
			continue
		}
		if err := s.sessionCache.Delete(ctx, candidate); err != nil {
			return nil, err
		}
	}

	revokedAccess, revokedRefresh, err := s.revokeUserTokens(ctx, userID, now)
	if err != nil {
		return nil, err
	}

	return &LogoutAllResult{
		SessionID:            sessionID,
		UserID:               strconv.FormatInt(userID, 10),
		RevokedSessionCount:  len(sessionIDs),
		RevokedAccessTokens:  revokedAccess,
		RevokedRefreshTokens: revokedRefresh,
	}, nil
}

func (s *Service) revokeUserTokens(ctx context.Context, userID int64, revokedAt time.Time) (int, int, error) {
	if s.tokens == nil {
		return 0, 0, nil
	}

	accessTokens, err := s.tokens.ListActiveAccessTokensByUserID(ctx, userID)
	if err != nil {
		return 0, 0, err
	}
	refreshTokens, err := s.tokens.ListActiveRefreshTokensByUserID(ctx, userID)
	if err != nil {
		return 0, 0, err
	}

	if err := s.tokens.RevokeAccessTokensByUserID(ctx, userID, revokedAt); err != nil {
		return 0, 0, err
	}
	if err := s.tokens.RevokeRefreshTokensByUserID(ctx, userID, revokedAt); err != nil {
		return 0, 0, err
	}

	if s.tokenCache != nil {
		for _, token := range accessTokens {
			if token == nil {
				continue
			}
			ttl := time.Until(token.ExpiresAt)
			if ttl <= 0 {
				continue
			}
			if err := s.tokenCache.RevokeAccessToken(ctx, token.TokenSHA256, ttl); err != nil {
				return 0, 0, err
			}
		}
		for _, token := range refreshTokens {
			if token == nil {
				continue
			}
			ttl := time.Until(token.ExpiresAt)
			if ttl <= 0 {
				continue
			}
			if err := s.tokenCache.RevokeRefreshToken(ctx, token.TokenSHA256, ttl); err != nil {
				return 0, 0, err
			}
		}
	}

	return len(accessTokens), len(refreshTokens), nil
}
