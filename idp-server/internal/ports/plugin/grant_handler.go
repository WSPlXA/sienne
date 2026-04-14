package plugin

import (
	"context"

	pkgoauth2 "idp-server/pkg/oauth2"
)

// GrantHandlerType 直接复用 OAuth2 grant_type，保持插件层和协议语义一致。
type GrantHandlerType = pkgoauth2.GrantType

type ExchangeInput struct {
	// 这里把不同 grant type 可能用到的字段统一摊平，
	// 具体 handler / service 只消费自己关心的那一部分。
	GrantType         pkgoauth2.GrantType
	ClientID          string
	ClientSecret      string
	ReplayFingerprint string
	Code              string
	RedirectURI       string
	CodeVerifier      string
	RefreshToken      string
	DeviceCode        string
	Username          string
	Password          string
	Scopes            []string
}

type ExchangeResult struct {
	// 返回结构对齐 token endpoint 的标准响应体。
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
	IDToken      string
}

// GrantHandler 表示一种 grant type 的兑换入口。
type GrantHandler interface {
	Name() string
	Type() GrantHandlerType
	Exchange(ctx context.Context, input ExchangeInput) (*ExchangeResult, error)
}
