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
		token := extractBearerToken(c.GetHeader("Authorization"))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing bearer token",
			})
			return
		}

		if m.tokenCache != nil {
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
