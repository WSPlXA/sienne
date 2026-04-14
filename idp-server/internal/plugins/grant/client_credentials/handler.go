package client_credentials

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

// NewHandler 注册 client_credentials grant 的插件适配器。
// 它本身不实现令牌签发逻辑，只负责把插件层输入转换成应用层
// ExchangeInput，让 token service 复用统一的签发与审计路径。
func NewHandler(exchanger apptoken.Exchanger) *Handler {
	return &Handler{
		name:      "client_credentials",
		exchanger: exchanger,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Type() pluginport.GrantHandlerType {
	return pkgoauth2.GrantTypeClientCredentials
}

// Exchange 校验插件被调用的 grant 类型是否匹配，然后把最小必要字段
// 转交给应用层。client_credentials 没有用户上下文，因此这里不会带 code、
// refresh token 或终端登录态，只围绕 client 本身完成交换。
func (h *Handler) Exchange(ctx context.Context, input pluginport.ExchangeInput) (*pluginport.ExchangeResult, error) {
	if h.exchanger == nil {
		return nil, errors.New("grant handler is not configured")
	}
	if input.GrantType == "" {
		input.GrantType = pkgoauth2.GrantTypeClientCredentials
	}
	if input.GrantType != pkgoauth2.GrantTypeClientCredentials {
		return nil, apptoken.ErrUnsupportedGrantType
	}

	result, err := h.exchanger.Exchange(ctx, apptoken.ExchangeInput{
		GrantType:         input.GrantType,
		ClientID:          input.ClientID,
		ClientSecret:      input.ClientSecret,
		ReplayFingerprint: input.ReplayFingerprint,
		Code:              input.Code,
		RedirectURI:       input.RedirectURI,
		CodeVerifier:      input.CodeVerifier,
		RefreshToken:      input.RefreshToken,
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
