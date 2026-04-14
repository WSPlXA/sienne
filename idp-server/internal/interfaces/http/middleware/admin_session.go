package middleware

import (
	"encoding/json"
	"net/http"
	"net/url"
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
		// 后台接口保护分三层：
		// 1. 有有效 session；
		// 2. session 已完成 MFA；
		// 3. 当前用户具备要求的 RBAC 权限。
		sessionID, _ := c.Cookie("idp_session")
		sessionID = strings.TrimSpace(sessionID)
		if sessionID == "" {
			m.abortUnauthorized(c, "login required")
			return
		}

		sessionModel, err := m.findSession(c, sessionID)
		if err != nil {
			m.abortUnauthorized(c, "invalid session")
			return
		}
		if sessionModel == nil || sessionModel.LoggedOutAt != nil || !sessionModel.ExpiresAt.After(m.now()) {
			m.abortUnauthorized(c, "session expired")
			return
		}
		if !sessionHasOTP(sessionModel) {
			// 后台敏感操作要求带有 OTP/MFA 级别的登录会话。
			m.abortUnauthorized(c, "mfa required")
			return
		}

		user, err := m.users.FindByID(c.Request.Context(), sessionModel.UserID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "permission lookup failed"})
			return
		}
		if user == nil || user.Status != "active" {
			m.abortForbidden(c, "user unavailable")
			return
		}
		if !rbac.HasAll(user.PrivilegeMask, required...) {
			m.abortForbidden(c, "insufficient privilege")
			return
		}

		c.Set(ContextAdminUser, user)
		c.Set(ContextAdminSession, sessionModel)
		// 通过后把当前管理员和会话对象挂进上下文，后续 handler 可直接复用。
		c.Next()
	}
}

func (m *SessionPermissionMiddleware) abortForbidden(c *gin.Context, message string) {
	// HTML 后台页面优先弹窗并返回上一页，API 调用则给纯 JSON。
	if wantsAdminHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(http.StatusForbidden)
		payload, _ := json.Marshal(strings.TrimSpace(message))
		_, _ = c.Writer.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>Forbidden</title></head><body><script>(function(){var msg=` + string(payload) + `||"insufficient privilege";window.alert(msg);if(window.history.length>1){window.history.back();return;}window.location.replace("/");})();</script></body></html>`))
		c.Abort()
		return
	}
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": message})
}

func (m *SessionPermissionMiddleware) abortUnauthorized(c *gin.Context, message string) {
	// 未登录和缺少 MFA 都属于“先补前置条件再回来”的场景，因此这里会带上当前 URL 做回跳。
	if wantsAdminHTML(c.GetHeader("Accept")) {
		if strings.EqualFold(strings.TrimSpace(message), "mfa required") {
			c.Redirect(http.StatusFound, "/mfa/totp/setup?return_to="+url.QueryEscape(c.Request.URL.RequestURI()))
			c.Abort()
			return
		}
		c.Redirect(http.StatusFound, "/login?return_to="+url.QueryEscape(c.Request.URL.RequestURI()))
		c.Abort()
		return
	}
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": message})
}

func (m *SessionPermissionMiddleware) findSession(c *gin.Context, sessionID string) (*sessiondomain.Model, error) {
	// 管理后台读 session 也优先走缓存，减少每次页面访问都打数据库。
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
	// 这是面向受信任缓存值的轻量解析器；遇到非法字符直接回退 0。
	var result int64
	for _, ch := range strings.TrimSpace(value) {
		if ch < '0' || ch > '9' {
			return 0
		}
		result = result*10 + int64(ch-'0')
	}
	return result
}

func wantsAdminHTML(accept string) bool {
	// 后台页只在明确声明 text/html 时走浏览器交互逻辑。
	accept = strings.ToLower(strings.TrimSpace(accept))
	return strings.Contains(accept, "text/html")
}

func CurrentAdminUser(c *gin.Context) *userdomain.Model {
	value, _ := c.Get(ContextAdminUser)
	user, _ := value.(*userdomain.Model)
	return user
}

func CurrentAdminSession(c *gin.Context) *sessiondomain.Model {
	value, _ := c.Get(ContextAdminSession)
	sessionModel, _ := value.(*sessiondomain.Model)
	return sessionModel
}

func sessionHasOTP(sessionModel *sessiondomain.Model) bool {
	// 这里通过 ACR/AMR 判定该会话是否包含第二要素认证结果。
	if sessionModel == nil {
		return false
	}
	amr := strings.ToLower(strings.TrimSpace(sessionModel.AMRJSON))
	if strings.Contains(amr, "\"otp\"") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(sessionModel.ACR), "urn:idp:acr:mfa")
}
