package token

import (
	"errors"

	pkgoauth2 "idp-server/pkg/oauth2"
)

var (
	ErrUnsupportedGrantType   = errors.New("unsupported grant type")
	ErrInvalidClient          = errors.New("invalid client")
	ErrInvalidScope           = errors.New("invalid scope")
	ErrInvalidCode            = errors.New("invalid authorization code")
	ErrInvalidRedirectURI     = errors.New("invalid redirect uri")
	ErrInvalidCodeVerifier    = errors.New("invalid code verifier")
	ErrInvalidRefreshToken    = errors.New("invalid refresh token")
	ErrInvalidUserCredentials = errors.New("invalid user credentials")
	ErrInvalidDeviceCode      = errors.New("invalid device code")
	ErrAuthorizationPending   = errors.New("authorization pending")
	ErrSlowDown               = errors.New("slow down")
	ErrAccessDenied           = errors.New("access denied")
)

type ExchangeInput struct {
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
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
	IDToken      string
}
