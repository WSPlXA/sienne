package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"

	appclientauth "idp-server/internal/application/clientauth"
	apptoken "idp-server/internal/application/token"
	"idp-server/internal/interfaces/http/dto"
	pluginregistry "idp-server/internal/plugins/registry"
	pluginport "idp-server/internal/ports/plugin"
	pkgoauth2 "idp-server/pkg/oauth2"

	"github.com/gin-gonic/gin"
)

type TokenHandler struct {
	clientAuthenticator appclientauth.Authenticator
	grantRegistry       *pluginregistry.GrantRegistry
}

func NewTokenHandler(clientAuthenticator appclientauth.Authenticator, grantRegistry *pluginregistry.GrantRegistry) *TokenHandler {
	return &TokenHandler{
		clientAuthenticator: clientAuthenticator,
		grantRegistry:       grantRegistry,
	}
}

func (h *TokenHandler) Handle(c *gin.Context) {
	// TokenHandler 是 OAuth2 token endpoint 的 HTTP 适配层：
	// 解析请求、认证 client、分发 grant type，再把结果序列化成标准响应。
	var req dto.TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "invalid_request",
			Description: "invalid token request",
		})
		return
	}

	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
		return
	}

	if h.clientAuthenticator == nil || h.grantRegistry == nil {
		c.JSON(http.StatusInternalServerError, pkgoauth2.Error{
			Code:        "server_error",
			Description: "token handler is not configured",
		})
		return
	}

	clientAuth, err := h.clientAuthenticator.Authenticate(c.Request.Context(), appclientauth.AuthenticateInput{
		AuthorizationHeader: c.GetHeader("Authorization"),
		ClientID:            req.ClientID,
		ClientSecret:        req.ClientSecret,
	})
	if err != nil {
		// token endpoint 上 client 认证失败通常要按 invalid_client 语义返回，
		// 只有真正的内部故障才升级成 server_error。
		log.Printf("client authentication failed grant_type=%s client_id=%s err=%v", req.GrantType, req.ClientID, err)
		var status int
		oauthErr := pkgoauth2.Error{
			Code:        "invalid_client",
			Description: err.Error(),
		}

		switch {
		case errors.Is(err, apptoken.ErrInvalidClient):
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
			oauthErr.Code = "server_error"
			oauthErr.Description = "client authentication failed"
		}

		c.JSON(status, oauthErr)
		return
	}

	clientID := clientAuth.ClientID
	clientSecret := clientAuth.ClientSecret
	grantType := pkgoauth2.GrantType(req.GrantType)
	grantHandler, ok := h.grantRegistry.Get(grantType)
	if !ok || grantHandler == nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "unsupported_grant_type",
			Description: "unsupported grant_type",
		})
		return
	}

	result, err := grantHandler.Exchange(c.Request.Context(), pluginport.ExchangeInput{
		// ReplayFingerprint 用于 refresh token 轮换时识别“同一客户端重试”与“异常重放”。
		GrantType:         grantType,
		ClientID:          clientID,
		ClientSecret:      clientSecret,
		ReplayFingerprint: buildRefreshReplayFingerprint(clientID, string(clientAuth.Method), c.ClientIP(), c.Request.UserAgent()),
		Code:              req.Code,
		RedirectURI:       req.RedirectURI,
		CodeVerifier:      req.CodeVerifier,
		RefreshToken:      req.RefreshToken,
		DeviceCode:        req.DeviceCode,
		Username:          req.Username,
		Password:          req.Password,
		Scopes:            req.ScopeList(),
	})
	if err != nil {
		// 这里把应用层错误转换为 OAuth2 标准错误码，客户端才能按规范重试或报错。
		log.Printf("token exchange failed grant_type=%s client_id=%s err=%v", req.GrantType, clientID, err)
		var status int
		oauthErr := pkgoauth2.Error{
			Code:        "invalid_grant",
			Description: err.Error(),
		}

		switch {
		case errors.Is(err, apptoken.ErrInvalidClient):
			status = http.StatusUnauthorized
			oauthErr.Code = "invalid_client"
		case errors.Is(err, apptoken.ErrInvalidScope):
			oauthErr.Code = "invalid_scope"
		case errors.Is(err, apptoken.ErrUnsupportedGrantType):
			oauthErr.Code = "unsupported_grant_type"
		case errors.Is(err, apptoken.ErrAuthorizationPending):
			oauthErr.Code = "authorization_pending"
			oauthErr.Description = err.Error()
		case errors.Is(err, apptoken.ErrSlowDown):
			oauthErr.Code = "slow_down"
			oauthErr.Description = err.Error()
		case errors.Is(err, apptoken.ErrAccessDenied):
			oauthErr.Code = "access_denied"
			oauthErr.Description = err.Error()
		case errors.Is(err, apptoken.ErrInvalidCode),
			errors.Is(err, apptoken.ErrInvalidRedirectURI),
			errors.Is(err, apptoken.ErrInvalidCodeVerifier),
			errors.Is(err, apptoken.ErrInvalidRefreshToken),
			errors.Is(err, apptoken.ErrInvalidDeviceCode),
			errors.Is(err, apptoken.ErrInvalidUserCredentials):
			oauthErr.Code = "invalid_grant"
		default:
			status = http.StatusInternalServerError
			oauthErr.Code = "server_error"
			oauthErr.Description = "token issuance failed"
		}

		c.JSON(status, oauthErr)
		return
	}

	// 成功时直接返回标准 token response。
	c.JSON(http.StatusOK, pkgoauth2.TokenResponse{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		Scope:        result.Scope,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IDToken,
	})
}

func buildRefreshReplayFingerprint(clientID, authMethod, clientIP, userAgent string) string {
	// 指纹不追求强身份认证，只用于把“同一个客户端环境的短时重试”聚合到一起。
	sum := sha256.Sum256([]byte(clientID + "|" + authMethod + "|" + clientIP + "|" + userAgent))
	return hex.EncodeToString(sum[:])
}
