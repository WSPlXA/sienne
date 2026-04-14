package refresh_token

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
		name:      "refresh_token",
		exchanger: exchanger,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Type() pluginport.GrantHandlerType {
	return pkgoauth2.GrantTypeRefreshToken
}

func (h *Handler) Exchange(ctx context.Context, input pluginport.ExchangeInput) (*pluginport.ExchangeResult, error) {
	// refresh token handler 与 authorization code handler 结构类似，
	// 但真正复杂的 replay 检测、轮换和 grace 逻辑都在 token service 里。
	if h.exchanger == nil {
		return nil, errors.New("grant handler is not configured")
	}
	if input.GrantType == "" {
		input.GrantType = pkgoauth2.GrantTypeRefreshToken
	}
	if input.GrantType != pkgoauth2.GrantTypeRefreshToken {
		return nil, apptoken.ErrUnsupportedGrantType
	}

	// ReplayFingerprint 会原样传入下层，用来识别同一客户端的并发重试与真实重放攻击。
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
