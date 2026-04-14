package client_secret_post

import (
	"context"
	"strings"

	apptoken "idp-server/internal/application/token"
	pluginport "idp-server/internal/ports/plugin"
	securityport "idp-server/internal/ports/security"
)

type Authenticator struct {
	passwords securityport.PasswordVerifier
}

// NewAuthenticator 提供 client_secret_post 认证方式的插件实现。
// token endpoint 会先根据 client 配置选择该插件，再把表单里的
// client_id/client_secret 交给它完成校验。
func NewAuthenticator(passwords securityport.PasswordVerifier) *Authenticator {
	return &Authenticator{passwords: passwords}
}

func (a *Authenticator) Name() string {
	return "client_secret_post"
}

func (a *Authenticator) Type() pluginport.ClientAuthMethodType {
	return pluginport.ClientAuthMethodClientSecretPost
}

// Authenticate 严格要求凭证来自请求体而不是 Authorization 头。
// 这样可以避免 client_secret_post 和 client_secret_basic 混用，
// 也让“客户端声明支持哪种认证方式”这一约束真正落到执行层。
func (a *Authenticator) Authenticate(ctx context.Context, input pluginport.ClientAuthenticateInput) (*pluginport.ClientAuthenticateResult, error) {
	_ = ctx
	if input.Client == nil || a.passwords == nil {
		return nil, apptoken.ErrInvalidClient
	}
	if strings.TrimSpace(input.AuthorizationHeader) != "" {
		return nil, apptoken.ErrInvalidClient
	}

	clientID := strings.TrimSpace(input.ClientID)
	clientSecret := input.ClientSecret
	if clientID == "" || clientSecret == "" || clientID != input.Client.ClientID {
		return nil, apptoken.ErrInvalidClient
	}
	if err := a.passwords.VerifyPassword(clientSecret, input.Client.ClientSecretHash); err != nil {
		return nil, apptoken.ErrInvalidClient
	}

	return &pluginport.ClientAuthenticateResult{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Method:       pluginport.ClientAuthMethodClientSecretPost,
	}, nil
}
