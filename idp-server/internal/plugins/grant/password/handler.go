package password

import (
	"context"
	"errors"

	apptoken "idp-server/internal/application/token"
	pluginport "idp-server/internal/ports/plugin"
	pkgoauth2 "idp-server/pkg/oauth2"
)

type Handler struct {
	name      string
	exchanger apptoken.Exchanger
}

// NewHandler 注册 password grant 的插件适配器。
// 这个 grant 已不推荐新系统使用，但保留该插件可以让老客户端在
// 明确启用时仍走统一的 token exchange 主链路。
func NewHandler(exchanger apptoken.Exchanger) *Handler {
	return &Handler{
		name:      "password",
		exchanger: exchanger,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Type() pluginport.GrantHandlerType {
	return pkgoauth2.GrantTypePassword
}

// Exchange 把资源所有者密码模式需要的用户名、密码和 scope 转给应用层。
// 真正的用户验证、MFA 约束和是否允许该 client 使用 password grant 的
// 决策不在这里做，而是交给下游服务统一判断。
func (h *Handler) Exchange(ctx context.Context, input pluginport.ExchangeInput) (*pluginport.ExchangeResult, error) {
	if h.exchanger == nil {
		return nil, errors.New("grant handler is not configured")
	}
	if input.GrantType == "" {
		input.GrantType = pkgoauth2.GrantTypePassword
	}
	if input.GrantType != pkgoauth2.GrantTypePassword {
		return nil, apptoken.ErrUnsupportedGrantType
	}

	result, err := h.exchanger.Exchange(ctx, apptoken.ExchangeInput{
		GrantType:         input.GrantType,
		ClientID:          input.ClientID,
		ClientSecret:      input.ClientSecret,
		ReplayFingerprint: input.ReplayFingerprint,
		Username:          input.Username,
		Password:          input.Password,
		Scopes:            input.Scopes,
	})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}

	return &pluginport.ExchangeResult{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
		Scope:        result.Scope,
		IDToken:      result.IDToken,
	}, nil
}
