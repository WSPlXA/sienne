package client

import "time"

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
