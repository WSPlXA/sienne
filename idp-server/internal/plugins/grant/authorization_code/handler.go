package authorization_code

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

func NewHandler(exchanger apptoken.Exchanger) *Handler {
	return &Handler{
		name:      "authorization_code",
		exchanger: exchanger,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Type() pluginport.GrantHandlerType {
	return pkgoauth2.GrantTypeAuthorizationCode
}

func (h *Handler) Exchange(ctx context.Context, input pluginport.ExchangeInput) (*pluginport.ExchangeResult, error) {
	// grant handler 本身不实现授权码兑换逻辑，
	// 它的职责是做协议级别的类型守卫，并把统一插件输入转换为 token service 输入。
	if h.exchanger == nil {
		return nil, errors.New("grant handler is not configured")
	}
	if input.GrantType == "" {
		input.GrantType = pkgoauth2.GrantTypeAuthorizationCode
	}
	if input.GrantType != pkgoauth2.GrantTypeAuthorizationCode {
		return nil, apptoken.ErrUnsupportedGrantType
	}

	// 实际的 code、redirect_uri、PKCE 校验都在 token service 中完成，
	// 这样不同入口不会复制一套兑换规则。
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

	// 最后再把应用层结果翻回插件端口类型，供 token handler 统一序列化响应。
	return &pluginport.ExchangeResult{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
		Scope:        result.Scope,
		IDToken:      result.IDToken,
	}, nil
}
