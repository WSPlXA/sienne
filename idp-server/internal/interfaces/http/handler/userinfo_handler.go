package handler

import (
	"errors"
	"net/http"
	"strings"

	"idp-server/internal/application/oidc"
	"idp-server/internal/interfaces/http/middleware"

	"github.com/gin-gonic/gin"
)

type UserInfoHandler struct {
	oidcService oidc.UserInfoProvider
}

func NewUserInfoHandler(oidcService oidc.UserInfoProvider) *UserInfoHandler {
	return &UserInfoHandler{oidcService: oidcService}
}

func (h *UserInfoHandler) Handle(c *gin.Context) {
	// userinfo endpoint 优先复用鉴权中间件已解析出来的 access token，
	// 中间件不存在时才从 Authorization 头自行提取。
	token := tokenFromContextOrHeader(c)
	result, err := h.oidcService.GetUserInfo(c.Request.Context(), oidc.UserInfoInput{
		AccessToken: token,
	})
	if err != nil {
		// userinfo 是资源接口语义：无效 token 返回 401，主体不存在返回 404。
		var status int
		switch {
		case errors.Is(err, oidc.ErrUserNotFound):
			status = http.StatusNotFound
		case errors.Is(err, oidc.ErrInvalidAccessToken):
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
		}

		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

func extractBearerToken(authorizationHeader string) string {
	// 这里与中间件保持相同的 Bearer 提取规则，避免行为分叉。
	if !strings.HasPrefix(authorizationHeader, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authorizationHeader, "Bearer "))
}

func tokenFromContextOrHeader(c *gin.Context) string {
	// 已经经过 RequireBearerToken 中间件时，可以直接取上下文，避免重复解析。
	if value, ok := c.Get(middleware.ContextAccessToken); ok {
		if token, ok := value.(string); ok && token != "" {
			return token
		}
	}

	return extractBearerToken(c.GetHeader("Authorization"))
}
