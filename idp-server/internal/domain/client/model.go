package client

import "time"

// Model 描述 OAuth/OIDC 客户端的注册信息。
// 它决定了这个客户端允许使用哪些 grant、怎样认证自己、以及 token/redirect 的安全边界。
type Model struct {
	ID                      int64
	ClientID                string
	ClientName              string
	ClientSecretHash        string
	ClientType              string
	TokenEndpointAuthMethod string
	RequirePKCE             bool
	RequireConsent          bool
	AccessTokenTTLSeconds   int
	RefreshTokenTTLSeconds  int
	IDTokenTTLSeconds       int
	Status                  string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	GrantTypes              []string
	AuthMethods             []string
	Scopes                  []string
	CreatedAt               time.Time
	UpdatedAt               time.Time
}
