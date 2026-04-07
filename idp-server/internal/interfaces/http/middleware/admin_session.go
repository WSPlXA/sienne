package middleware

import (
	"net/http"
	"strings"
	"time"

	sessiondomain "idp-server/internal/domain/session"
	userdomain "idp-server/internal/domain/user"
	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
	"idp-server/pkg/rbac"

	"github.com/gin-gonic/gin"
)

const (
	ContextAdminUser    = "admin_user"
	ContextAdminSession = "admin_session"
)

type SessionPermissionMiddleware struct {
	sessions     repository.SessionRepository
	sessionCache cacheport.SessionCacheRepository
	users        repository.UserRepository
	now          func() time.Time
}

func NewSessionPermissionMiddleware(sessions repository.SessionRepository, sessionCache cacheport.SessionCacheRepository, users repository.UserRepository) *SessionPermissionMiddleware {
	return &SessionPermissionMiddleware{
		sessions:     sessions,
		sessionCache: sessionCache,
		users:        users,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (m *SessionPermissionMiddleware) RequireSessionPermissions(required ...uint32) gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionID, _ := c.Cookie("idp_session")
		sessionID = strings.TrimSpace(sessionID)
		if sessionID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "login required"})
			return
		}

		sessionModel, err := m.findSession(c, sessionID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
			return
		}
		if sessionModel == nil || sessionModel.LoggedOutAt != nil || !sessionModel.ExpiresAt.After(m.now()) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
			return
		}

		user, err := m.users.FindByID(c.Request.Context(), sessionModel.UserID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "permission lookup failed"})
			return
		}
		if user == nil || user.Status != "active" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "user unavailable"})
			return
		}
		if !rbac.HasAll(user.PrivilegeMask, required...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient privilege"})
			return
		}

		c.Set(ContextAdminUser, user)
		c.Set(ContextAdminSession, sessionModel)
		c.Next()
	}
}

func (m *SessionPermissionMiddleware) findSession(c *gin.Context, sessionID string) (*sessiondomain.Model, error) {
	if m.sessionCache != nil {
		entry, err := m.sessionCache.Get(c.Request.Context(), sessionID)
		if err != nil {
			return nil, err
		}
		if entry != nil && entry.ExpiresAt.After(m.now()) && strings.EqualFold(strings.TrimSpace(entry.Status), "active") {
			return &sessiondomain.Model{
				SessionID:       entry.SessionID,
				UserID:          mustParseInt64(entry.UserID),
				Subject:         entry.Subject,
				ACR:             entry.ACR,
				AMRJSON:         entry.AMRJSON,
				IPAddress:       entry.IPAddress,
				UserAgent:       entry.UserAgent,
				AuthenticatedAt: entry.AuthenticatedAt,
				ExpiresAt:       entry.ExpiresAt,
			}, nil
		}
	}
	return m.sessions.FindBySessionID(c.Request.Context(), sessionID)
}

func mustParseInt64(value string) int64 {
	var result int64
	for _, ch := range strings.TrimSpace(value) {
		if ch < '0' || ch > '9' {
			return 0
		}
		result = result*10 + int64(ch-'0')
	}
	return result
}

func CurrentAdminUser(c *gin.Context) *userdomain.Model {
	value, _ := c.Get(ContextAdminUser)
	user, _ := value.(*userdomain.Model)
	return user
}
