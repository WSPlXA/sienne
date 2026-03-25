package password

import (
	"context"
	"strings"

	appauthn "idp-server/internal/application/authn"
	pluginport "idp-server/internal/ports/plugin"
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"
)

type Method struct {
	name      string
	users     repository.UserRepository
	passwords securityport.PasswordVerifier
}

func NewMethod(users repository.UserRepository, passwords securityport.PasswordVerifier) *Method {
	return &Method{
		name:      "password",
		users:     users,
		passwords: passwords,
	}
}

func (m *Method) Name() string {
	return m.name
}

func (m *Method) Type() pluginport.AuthnMethodType {
	return pluginport.AuthnMethodTypePassword
}

func (m *Method) Authenticate(ctx context.Context, input pluginport.AuthenticateInput) (*pluginport.AuthenticateResult, error) {
	username := strings.TrimSpace(input.Username)
	if username == "" || input.Password == "" || m.users == nil || m.passwords == nil {
		return nil, appauthn.ErrInvalidCredentials
	}

	user := input.User
	if user == nil {
		var err error
		user, err = m.users.FindByUsername(ctx, username)
		if err != nil {
			return nil, err
		}
	}
	if user == nil {
		return nil, appauthn.ErrInvalidCredentials
	}
	if user.Status == "locked" {
		return nil, appauthn.ErrUserLocked
	}
	if user.Status != "" && user.Status != "active" {
		return nil, appauthn.ErrUserDisabled
	}

	if err := m.passwords.VerifyPassword(input.Password, user.PasswordHash); err != nil {
		return nil, appauthn.ErrInvalidCredentials
	}

	return &pluginport.AuthenticateResult{
		Handled:       true,
		Authenticated: true,
		UserID:        user.ID,
		UserStatus:    user.Status,
		Subject:       user.UserUUID,
		Username:      user.Username,
		DisplayName:   user.DisplayName,
		Email:         user.Email,
	}, nil
}
