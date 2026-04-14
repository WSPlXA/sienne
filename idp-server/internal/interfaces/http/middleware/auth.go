package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"

	cacheport "idp-server/internal/ports/cache"

	"github.com/gin-gonic/gin"
)

const (
	ContextAccessToken = "access_token"
	ContextTokenClaims = "token_claims"
	ContextSubject     = "subject"
	ContextClientID    = "client_id"
)

type tokenValidator interface {
	ParseAndValidate(token string, opts ValidateOptions) (map[string]any, error)
}

type ValidateOptions struct {
	Issuer string
}

// AuthMiddleware 负责把 Bearer Token 校验结果注入 Gin 上下文。
// 它位于 HTTP 边界层，因此只做协议相关判断，不直接碰业务仓储。
type AuthMiddleware struct {
	tokens     tokenValidator
	tokenCache cacheport.TokenCacheRepository
	issuer     string
}

func NewAuthMiddleware(tokens tokenValidator, tokenCache cacheport.TokenCacheRepository, issuer string) *AuthMiddleware {
	return &AuthMiddleware{
		tokens:     tokens,
		tokenCache: tokenCache,
		issuer:     issuer,
	}
}

func (m *AuthMiddleware) RequireBearerToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 第一步只负责从 Authorization 头里提取 Bearer Token，
		// 格式不对时直接在网关层返回 401。
		token := extractBearerToken(c.GetHeader("Authorization"))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing bearer token",
			})
			return
		}

		if m.tokenCache != nil {
			// 对 JWT 来说，“签名有效”不等于“还允许使用”。
			// 这里额外查询撤销状态，覆盖主动登出/强制下线场景。
			revoked, err := m.tokenCache.IsAccessTokenRevoked(c.Request.Context(), sha256Hex(token))
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid access token",
				})
				return
			}
			if revoked {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "access token revoked",
				})
				return
			}
		}

		if m.tokens != nil {
			// 签名和基础 claim 校验通过后，把常用 claim 挂进上下文，
			// 后续 handler 就不用再次解析 token。
			claims, err := m.tokens.ParseAndValidate(token, ValidateOptions{
				Issuer: m.issuer,
			})
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "invalid access token",
				})
				return
			}
			c.Set(ContextTokenClaims, claims)
			if subject, ok := claims["sub"].(string); ok && subject != "" {
				c.Set(ContextSubject, subject)
			}
			if clientID, ok := claims["cid"].(string); ok && clientID != "" {
				c.Set(ContextClientID, clientID)
			}
		}

		c.Set(ContextAccessToken, token)
		c.Next()
	}
}

func extractBearerToken(authorizationHeader string) string {
	// 这里只接受标准的 "Bearer <token>" 形式，故意不做更宽松的兼容，
	// 这样可以减少模糊输入带来的歧义。
	if !strings.HasPrefix(authorizationHeader, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authorizationHeader, "Bearer "))
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

type tokenRevocationChecker interface {
	IsAccessTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error)
}
