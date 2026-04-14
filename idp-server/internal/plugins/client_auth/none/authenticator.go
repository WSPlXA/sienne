package none

import (
	"context"
	"strings"

	apptoken "idp-server/internal/application/token"
	pluginport "idp-server/internal/ports/plugin"
)

type Authenticator struct{}

// NewAuthenticator 返回 public client 使用的 "none" 认证实现。
// 这类客户端没有保密能力，所以服务端只能确认 client_id 本身，
// 并依赖 PKCE、redirect URI 等其他机制补足安全性。
func NewAuthenticator() *Authenticator {
	return &Authenticator{}
}

func (a *Authenticator) Name() string {
	return "none"
}

func (a *Authenticator) Type() pluginport.ClientAuthMethodType {
	return pluginport.ClientAuthMethodNone
}

// Authenticate 要求请求里不能夹带 Authorization 头或 client secret，
// 否则说明调用方和 client 配置不一致，应按 invalid_client 拒绝。
func (a *Authenticator) Authenticate(ctx context.Context, input pluginport.ClientAuthenticateInput) (*pluginport.ClientAuthenticateResult, error) {
	_ = ctx
	if input.Client == nil {
		return nil, apptoken.ErrInvalidClient
	}
	if strings.TrimSpace(input.AuthorizationHeader) != "" {
		return nil, apptoken.ErrInvalidClient
	}
	if strings.TrimSpace(input.ClientSecret) != "" {
		return nil, apptoken.ErrInvalidClient
	}

	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" || clientID != input.Client.ClientID {
		return nil, apptoken.ErrInvalidClient
	}

	return &pluginport.ClientAuthenticateResult{
		ClientID:     clientID,
		ClientSecret: "",
		Method:       pluginport.ClientAuthMethodNone,
	}, nil
}
