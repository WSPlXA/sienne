package plugin

import (
	"context"

	userdomain "idp-server/internal/domain/user"
)

type AuthnMethodType string

const (
	AuthnMethodTypePassword      AuthnMethodType = "password"
	AuthnMethodTypeFederatedOIDC AuthnMethodType = "federated_oidc"
)

type AuthenticateInput struct {
	Username    string
	Password    string
	RedirectURI string
	ReturnTo    string
	State       string
	Code        string
	Nonce       string
	User        *userdomain.Model
}

type AuthenticateResult struct {
	Handled          bool
	Authenticated    bool
	UserID           int64
	UserStatus       string
	Subject          string
	IdentityProvider string
	Username         string
	DisplayName      string
	Email            string
	RedirectURI      string
}

type AuthnMethod interface {
	Name() string
	Type() AuthnMethodType
	Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error)
}
