package oidc

import (
	"errors"
	"time"
)

var (
	ErrInvalidAccessToken = errors.New("invalid access token")
	ErrUserNotFound       = errors.New("user not found")
)

type UserInfoInput struct {
	AccessToken string
}

type UserInfoOutput struct {
	Subject       string `json:"sub"`
	Name          string `json:"name,omitempty"`
	PreferredName string `json:"preferred_username,omitempty"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
}

type DiscoveryDocument struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	UserInfoEndpoint                          string   `json:"userinfo_endpoint"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint,omitempty"`
	EndSessionEndpoint                        string   `json:"end_session_endpoint,omitempty"`
	JWKSURI                                   string   `json:"jwks_uri"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported          []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                           []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
}

type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

type JSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type IntrospectionInput struct {
	AccessToken string
}

type IntrospectionOutput struct {
	Active    bool      `json:"active"`
	Scope     string    `json:"scope,omitempty"`
	ClientID  string    `json:"client_id,omitempty"`
	TokenType string    `json:"token_type,omitempty"`
	Exp       int64     `json:"exp,omitempty"`
	Iat       int64     `json:"iat,omitempty"`
	Nbf       int64     `json:"nbf,omitempty"`
	Sub       string    `json:"sub,omitempty"`
	Aud       []string  `json:"aud,omitempty"`
	Iss       string    `json:"iss,omitempty"`
	Jti       string    `json:"jti,omitempty"`
	Username  string    `json:"username,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}
