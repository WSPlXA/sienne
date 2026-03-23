package token

import (
	"errors"

	pkgoauth2 "idp-server/pkg/oauth2"
)

var (
	ErrUnsupportedGrantType = errors.New("unsupported grant type")
	ErrInvalidClient        = errors.New("invalid client")
	ErrInvalidScope         = errors.New("invalid scope")
	ErrInvalidCode          = errors.New("invalid authorization code")
	ErrInvalidRedirectURI   = errors.New("invalid redirect uri")
	ErrInvalidCodeVerifier  = errors.New("invalid code verifier")
	ErrInvalidRefreshToken  = errors.New("invalid refresh token")
)

type ExchangeInput struct {
	GrantType    pkgoauth2.GrantType
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	Scopes       []string
}

type ExchangeResult struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
	IDToken      string
}
