package session

import (
	"context"
	"strconv"
	"strings"
	"time"

	"idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
)

type Manager interface {
	Logout(ctx context.Context, input LogoutInput) (*LogoutResult, error)
}

type Service struct {
	sessions     repository.SessionRepository
	sessionCache cache.SessionCacheRepository
	now          func() time.Time
}

func NewService(
	sessions repository.SessionRepository,
	sessionCache cache.SessionCacheRepository,
) *Service {
	return &Service{
		sessions:     sessions,
		sessionCache: sessionCache,
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
