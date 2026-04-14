package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	appclientauth "idp-server/internal/application/clientauth"
	appdevice "idp-server/internal/application/device"
	apptoken "idp-server/internal/application/token"
	"idp-server/internal/interfaces/http/dto"

	"github.com/gin-gonic/gin"
)

type DeviceAuthorizeHandler struct {
	clientAuthenticator appclientauth.Authenticator
	starter             appdevice.Starter
}

func NewDeviceAuthorizeHandler(clientAuthenticator appclientauth.Authenticator, starter appdevice.Starter) *DeviceAuthorizeHandler {
	return &DeviceAuthorizeHandler{
		clientAuthenticator: clientAuthenticator,
		starter:             starter,
	}
}

func (h *DeviceAuthorizeHandler) Handle(c *gin.Context) {
	// 这是 device flow 的“设备端入口”：
	// 设备先做 client 认证，然后向服务端申请 device_code / user_code。
	var req dto.DeviceAuthorizeRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid device authorization request"})
		return
	}
	if h.clientAuthenticator == nil || h.starter == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "device authorization is not configured"})
		return
	}

	clientAuth, err := h.clientAuthenticator.Authenticate(c.Request.Context(), appclientauth.AuthenticateInput{
		AuthorizationHeader: c.GetHeader("Authorization"),
		ClientID:            req.ClientID,
		ClientSecret:        req.ClientSecret,
	})
	if err != nil {
		// 设备授权接口和 token endpoint 一样，client 认证失败按 invalid_client 语义处理。
		status := http.StatusUnauthorized
		code := "invalid_client"
		if !errors.Is(err, apptoken.ErrInvalidClient) {
			status = http.StatusInternalServerError
			code = "server_error"
		}
		c.JSON(status, gin.H{"error": code})
		return
	}

	result, err := h.starter.Start(c.Request.Context(), appdevice.StartInput{
		ClientID: clientAuth.ClientID,
		Scopes:   req.ScopeList(),
	})
	if err != nil {
		// scope 或 client 不合法时，直接返回标准化错误码给设备端。
		switch {
		case errors.Is(err, appdevice.ErrInvalidClient):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		case errors.Is(err, appdevice.ErrInvalidScope):
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_scope"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		}
		return
	}

	verificationURI := deviceVerificationURI(c)
	// verification_uri_complete 允许用户直接扫码/点击带着 user_code 进入确认页。
	c.JSON(http.StatusOK, gin.H{
		"device_code":               result.DeviceCode,
		"user_code":                 result.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + result.UserCode,
		"expires_in":                int64(time.Until(result.ExpiresAt).Seconds()),
		"interval":                  result.Interval,
	})
}

func deviceVerificationURI(c *gin.Context) string {
	// 尽量尊重反向代理透传的协议头，保证对外暴露的 verification_uri 可被真实客户端访问。
	scheme := "http"
	if proto := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); proto != "" {
		scheme = proto
	} else if c.Request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + c.Request.Host + "/device"
}
