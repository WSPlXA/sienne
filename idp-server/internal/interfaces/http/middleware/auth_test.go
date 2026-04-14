package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	cacheport "idp-server/internal/ports/cache"

	"github.com/gin-gonic/gin"
)

type stubTokenValidator struct {
	claims map[string]any
	err    error
}

func (s *stubTokenValidator) ParseAndValidate(_ string, _ ValidateOptions) (map[string]any, error) {
	return s.claims, s.err
}

type stubAccessTokenCache struct {
	revoked bool
	err     error
}

func (s *stubAccessTokenCache) SaveAccessToken(context.Context, cacheport.AccessTokenCacheEntry, time.Duration) error {
	return nil
}

func (s *stubAccessTokenCache) GetAccessToken(context.Context, string) (*cacheport.AccessTokenCacheEntry, error) {
	return nil, nil
}

func (s *stubAccessTokenCache) SaveRefreshToken(context.Context, cacheport.RefreshTokenCacheEntry, time.Duration) error {
	return nil
}

func (s *stubAccessTokenCache) GetRefreshToken(context.Context, string) (*cacheport.RefreshTokenCacheEntry, error) {
	return nil, nil
}

func (s *stubAccessTokenCache) CheckRefreshTokenReplay(context.Context, string, string) (*cacheport.RefreshTokenReplayResult, error) {
	return &cacheport.RefreshTokenReplayResult{Status: cacheport.RefreshTokenReplayNone}, nil
}

func (s *stubAccessTokenCache) RotateRefreshToken(context.Context, string, cacheport.RefreshTokenCacheEntry, cacheport.TokenResponseCacheEntry, string, time.Duration, time.Duration) error {
	return nil
}

func (s *stubAccessTokenCache) RevokeAccessToken(context.Context, string, time.Duration) error {
	return nil
}

func (s *stubAccessTokenCache) RevokeRefreshToken(context.Context, string, time.Duration) error {
	return nil
}

func (s *stubAccessTokenCache) IsAccessTokenRevoked(context.Context, string) (bool, error) {
	return s.revoked, s.err
}

func (s *stubAccessTokenCache) IsRefreshTokenRevoked(context.Context, string) (bool, error) {
	return false, nil
}

func TestRequireBearerTokenRejectsRevokedToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/userinfo", NewAuthMiddleware(&stubTokenValidator{}, &stubAccessTokenCache{revoked: true}, "issuer").RequireBearerToken(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer token-value")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if body := recorder.Body.String(); body == "" {
		t.Fatal("expected error response body")
	}
}

func TestRequireBearerTokenAllowsActiveToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/userinfo", NewAuthMiddleware(&stubTokenValidator{claims: map[string]any{"sub": "user-1", "cid": "client-1"}}, &stubAccessTokenCache{}, "issuer").RequireBearerToken(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer token-value")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestRequireBearerTokenRejectsCacheError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/userinfo", NewAuthMiddleware(&stubTokenValidator{}, &stubAccessTokenCache{err: errors.New("redis down")}, "issuer").RequireBearerToken(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer token-value")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}
