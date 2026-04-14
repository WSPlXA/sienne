package device_code

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

// NewHandler 注册 device_code grant 的插件适配器。
// 设备授权的轮询、授权状态判断和节流策略都在应用层，这里只承担
// grant 插件统一入口的胶水职责。
func NewHandler(exchanger apptoken.Exchanger) *Handler {
	return &Handler{
		name:      "device_code",
		exchanger: exchanger,
	}
}

func (h *Handler) Name() string {
	return h.name
}

func (h *Handler) Type() pluginport.GrantHandlerType {
	return pkgoauth2.GrantTypeDeviceCode
}

// Exchange 只接收设备端轮询 token endpoint 时真正需要的 device_code
// 等字段，并把 grant 类型固定到 device_code，避免插件被错误复用到
// 其他交换路径。
func (h *Handler) Exchange(ctx context.Context, input pluginport.ExchangeInput) (*pluginport.ExchangeResult, error) {
	if h.exchanger == nil {
		return nil, errors.New("grant handler is not configured")
	}
	if input.GrantType == "" {
		input.GrantType = pkgoauth2.GrantTypeDeviceCode
	}
	if input.GrantType != pkgoauth2.GrantTypeDeviceCode {
		return nil, apptoken.ErrUnsupportedGrantType
	}

	result, err := h.exchanger.Exchange(ctx, apptoken.ExchangeInput{
		GrantType:         input.GrantType,
		ClientID:          input.ClientID,
		ClientSecret:      input.ClientSecret,
		ReplayFingerprint: input.ReplayFingerprint,
		DeviceCode:        input.DeviceCode,
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
