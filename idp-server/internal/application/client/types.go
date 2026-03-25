package client

import (
	"context"
	"errors"
)

var (
	ErrInvalidClientID       = errors.New("invalid client id")
	ErrClientIDAlreadyExists = errors.New("client id already exists")
	ErrClientNotFound        = errors.New("client not found")
	ErrInvalidClientName     = errors.New("invalid client name")
	ErrInvalidClientType     = errors.New("invalid client type")
	ErrInvalidClientSecret   = errors.New("invalid client secret")
	ErrInvalidAuthMethod     = errors.New("invalid token endpoint auth method")
	ErrInvalidGrantType      = errors.New("invalid grant type")
	ErrInvalidScope          = errors.New("invalid scope")
	ErrRedirectURIRequired   = errors.New("redirect uri is required")
	ErrInvalidRedirectURI    = errors.New("invalid redirect uri")
	ErrInvalidClientConfig   = errors.New("invalid client configuration")
)

type CreateClientInput struct {
	ClientID                string
	ClientName              string
	ClientSecret            string
	ClientType              string
	TokenEndpointAuthMethod string
	RequirePKCE             *bool
	RequireConsent          *bool
	AccessTokenTTLSeconds   int
	RefreshTokenTTLSeconds  int
	IDTokenTTLSeconds       int
	GrantTypes              []string
	Scopes                  []string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	Status                  string
}

type CreateClientResult struct {
	ClientID                string
	ClientName              string
	ClientType              string
	TokenEndpointAuthMethod string
	RequirePKCE             bool
	RequireConsent          bool
	AccessTokenTTLSeconds   int
	RefreshTokenTTLSeconds  int
	IDTokenTTLSeconds       int
	GrantTypes              []string
	AuthMethods             []string
	Scopes                  []string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	Status                  string
}

type RegisterRedirectURIsInput struct {
	ClientID     string
	RedirectURIs []string
}

type RegisterRedirectURIsResult struct {
	ClientID        string
	ClientName      string
	RedirectURIs    []string
	RegisteredCount int
	SkippedCount    int
}

type RegisterPostLogoutRedirectURIsInput struct {
	ClientID     string
	RedirectURIs []string
}

type RegisterPostLogoutRedirectURIsResult struct {
	ClientID        string
	ClientName      string
	RedirectURIs    []string
	RegisteredCount int
	SkippedCount    int
}

type LogoutRedirectValidator interface {
	ValidatePostLogoutRedirectURI(ctx context.Context, input ValidatePostLogoutRedirectURIInput) (*ValidatePostLogoutRedirectURIResult, error)
}

type ValidatePostLogoutRedirectURIInput struct {
	ClientID    string
	RedirectURI string
}

type ValidatePostLogoutRedirectURIResult struct {
	ClientID    string
	ClientName  string
	RedirectURI string
}
