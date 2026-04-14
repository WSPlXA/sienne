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

// Service 负责“退出登录”相关的会话和 token 收尾工作。
// 它不仅要删除浏览器会话，还要尽量把同一用户的服务端状态一起清理干净，
// 避免出现页面已退出、API token 仍然可用的割裂状态。
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
	// 单点登出只处理当前 session，不影响同一用户的其他设备或其他 token。
	sessionID := strings.TrimSpace(input.SessionID)
	if sessionID == "" {
		return &LogoutResult{}, nil
	}

	sessionModel, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if sessionModel == nil {
		// 数据库里已经没有这个会话时，仍然顺手删掉缓存，做一次幂等清理。
		if s.sessionCache != nil {
			if err := s.sessionCache.Delete(ctx, sessionID); err != nil {
				return nil, err
			}
		}
		return &LogoutResult{}, nil
	}

	if sessionModel.LoggedOutAt == nil {
		// 先落库标记退出，再清缓存，保证数据库始终是最终真相来源。
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
	// LogoutAll 以当前 session 为入口，找到所属用户后扩散到该用户的所有活跃会话。
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
	// 管理员强制下线不依赖当前会话，只需要明确目标用户即可。
	if input.UserID <= 0 {
		return &LogoutAllResult{}, nil
	}
	return s.logoutUser(ctx, input.UserID, "")
}

func (s *Service) collectUserSessionIDs(ctx context.Context, userID int64, activeSessions []*sessiondomain.Model) ([]string, error) {
	// 会话 ID 同时存在于数据库和缓存的索引集合中，
	// 这里要把两边结果合并去重，尽量做到“清一次就清干净”。
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
	// 统一的“整用户登出”路径：
	// 先使所有 session 失效，再清缓存，最后撤销 access/refresh token。
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
	// token 撤销除了更新数据库状态，还要把剩余 TTL 写进缓存黑名单，
	// 这样中间件可以在 JWT 尚未自然过期前立即拦截它。
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
			ttl := token.ExpiresAt.Sub(revokedAt)
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
			ttl := token.ExpiresAt.Sub(revokedAt)
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
