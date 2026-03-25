package client

import (
	"context"
	"net/url"
	"regexp"
	"slices"
	"strings"

	clientdomain "idp-server/internal/domain/client"
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"
)

var clientIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{3,128}$`)

var supportedGrantTypes = []string{
	"authorization_code",
	"refresh_token",
	"client_credentials",
}

type Registrar interface {
	RegisterRedirectURIs(ctx context.Context, input RegisterRedirectURIsInput) (*RegisterRedirectURIsResult, error)
}

type PostLogoutRegistrar interface {
	RegisterPostLogoutRedirectURIs(ctx context.Context, input RegisterPostLogoutRedirectURIsInput) (*RegisterPostLogoutRedirectURIsResult, error)
}

type Creator interface {
	CreateClient(ctx context.Context, input CreateClientInput) (*CreateClientResult, error)
}

type Service struct {
	clients   repository.ClientRepository
	passwords securityport.PasswordVerifier
}

func NewService(clients repository.ClientRepository, passwords securityport.PasswordVerifier) *Service {
	return &Service{
		clients:   clients,
		passwords: passwords,
	}
}

func (s *Service) CreateClient(ctx context.Context, input CreateClientInput) (*CreateClientResult, error) {
	clientID := strings.TrimSpace(input.ClientID)
	clientName := strings.TrimSpace(input.ClientName)

	if !clientIDPattern.MatchString(clientID) {
		return nil, ErrInvalidClientID
	}
	if len(clientName) < 2 || len(clientName) > 128 {
		return nil, ErrInvalidClientName
	}

	existing, err := s.clients.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrClientIDAlreadyExists
	}

	clientType, authMethod, requirePKCE, requireConsent, err := s.normalizeClientSettings(input)
	if err != nil {
		return nil, err
	}

	grantTypes, err := normalizeGrantTypes(input.GrantTypes)
	if err != nil {
		return nil, err
	}
	if clientType != "confidential" && containsString(grantTypes, "client_credentials") {
		return nil, ErrInvalidClientConfig
	}
	scopes, err := normalizeScopes(input.Scopes)
	if err != nil {
		return nil, err
	}
	redirectURIs, err := normalizeClientRedirectURIs(input.RedirectURIs, grantTypes)
	if err != nil {
		return nil, err
	}
	postLogoutRedirectURIs, err := normalizeOptionalRedirectURIs(input.PostLogoutRedirectURIs)
	if err != nil {
		return nil, err
	}

	secretHash, err := s.normalizeClientSecret(clientType, authMethod, strings.TrimSpace(input.ClientSecret))
	if err != nil {
		return nil, err
	}

	model := &clientdomain.Model{
		ClientID:                clientID,
		ClientName:              clientName,
		ClientSecretHash:        secretHash,
		ClientType:              clientType,
		TokenEndpointAuthMethod: authMethod,
		RequirePKCE:             requirePKCE,
		RequireConsent:          requireConsent,
		AccessTokenTTLSeconds:   normalizeTTL(input.AccessTokenTTLSeconds, 3600),
		RefreshTokenTTLSeconds:  normalizeRefreshTTL(input.RefreshTokenTTLSeconds, grantTypes),
		IDTokenTTLSeconds:       normalizeIDTokenTTL(input.IDTokenTTLSeconds, grantTypes),
		Status:                  normalizeStatus(input.Status),
		RedirectURIs:            redirectURIs,
		PostLogoutRedirectURIs:  postLogoutRedirectURIs,
		GrantTypes:              grantTypes,
		AuthMethods:             []string{authMethod},
		Scopes:                  scopes,
	}

	if err := s.clients.CreateClient(ctx, model); err != nil {
		return nil, err
	}

	return &CreateClientResult{
		ClientID:                model.ClientID,
		ClientName:              model.ClientName,
		ClientType:              model.ClientType,
		TokenEndpointAuthMethod: model.TokenEndpointAuthMethod,
		RequirePKCE:             model.RequirePKCE,
		RequireConsent:          model.RequireConsent,
		AccessTokenTTLSeconds:   model.AccessTokenTTLSeconds,
		RefreshTokenTTLSeconds:  model.RefreshTokenTTLSeconds,
		IDTokenTTLSeconds:       model.IDTokenTTLSeconds,
		GrantTypes:              append([]string(nil), model.GrantTypes...),
		AuthMethods:             append([]string(nil), model.AuthMethods...),
		Scopes:                  append([]string(nil), model.Scopes...),
		RedirectURIs:            append([]string(nil), model.RedirectURIs...),
		PostLogoutRedirectURIs:  append([]string(nil), model.PostLogoutRedirectURIs...),
		Status:                  model.Status,
	}, nil
}

func (s *Service) RegisterRedirectURIs(ctx context.Context, input RegisterRedirectURIsInput) (*RegisterRedirectURIsResult, error) {
	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" {
		return nil, ErrInvalidClientID
	}

	redirectURIs, err := normalizeRedirectURIs(input.RedirectURIs)
	if err != nil {
		return nil, err
	}

	model, err := s.clients.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if model == nil {
		return nil, ErrClientNotFound
	}

	insertedCount, err := s.clients.RegisterRedirectURIs(ctx, model.ID, redirectURIs)
	if err != nil {
		return nil, err
	}

	return &RegisterRedirectURIsResult{
		ClientID:        model.ClientID,
		ClientName:      model.ClientName,
		RedirectURIs:    redirectURIs,
		RegisteredCount: insertedCount,
		SkippedCount:    len(redirectURIs) - insertedCount,
	}, nil
}

func (s *Service) RegisterPostLogoutRedirectURIs(ctx context.Context, input RegisterPostLogoutRedirectURIsInput) (*RegisterPostLogoutRedirectURIsResult, error) {
	clientID := strings.TrimSpace(input.ClientID)
	if clientID == "" {
		return nil, ErrInvalidClientID
	}

	redirectURIs, err := normalizeRedirectURIs(input.RedirectURIs)
	if err != nil {
		return nil, err
	}

	model, err := s.clients.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if model == nil {
		return nil, ErrClientNotFound
	}

	insertedCount, err := s.clients.RegisterPostLogoutRedirectURIs(ctx, model.ID, redirectURIs)
	if err != nil {
		return nil, err
	}

	return &RegisterPostLogoutRedirectURIsResult{
		ClientID:        model.ClientID,
		ClientName:      model.ClientName,
		RedirectURIs:    redirectURIs,
		RegisteredCount: insertedCount,
		SkippedCount:    len(redirectURIs) - insertedCount,
	}, nil
}

func (s *Service) ValidatePostLogoutRedirectURI(ctx context.Context, input ValidatePostLogoutRedirectURIInput) (*ValidatePostLogoutRedirectURIResult, error) {
	clientID := strings.TrimSpace(input.ClientID)
	redirectURI := strings.TrimSpace(input.RedirectURI)
	if clientID == "" || redirectURI == "" {
		return nil, ErrInvalidRedirectURI
	}

	model, err := s.clients.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if model == nil || model.Status != "active" {
		return nil, ErrClientNotFound
	}
	registered, err := s.clients.HasPostLogoutRedirectURI(ctx, model.ID, redirectURI)
	if err != nil {
		return nil, err
	}
	if !registered {
		return nil, ErrInvalidRedirectURI
	}

	return &ValidatePostLogoutRedirectURIResult{
		ClientID:    model.ClientID,
		ClientName:  model.ClientName,
		RedirectURI: redirectURI,
	}, nil
}

func (s *Service) normalizeClientSettings(input CreateClientInput) (string, string, bool, bool, error) {
	clientType := strings.ToLower(strings.TrimSpace(input.ClientType))
	if clientType == "" {
		clientType = "confidential"
	}
	if clientType != "confidential" && clientType != "public" {
		return "", "", false, false, ErrInvalidClientType
	}

	authMethod := strings.ToLower(strings.TrimSpace(input.TokenEndpointAuthMethod))
	if authMethod == "" {
		if clientType == "public" {
			authMethod = "none"
		} else {
			authMethod = "client_secret_basic"
		}
	}

	switch authMethod {
	case "client_secret_basic", "client_secret_post", "none":
	default:
		return "", "", false, false, ErrInvalidAuthMethod
	}

	switch {
	case clientType == "public" && authMethod != "none":
		return "", "", false, false, ErrInvalidClientConfig
	case clientType == "confidential" && authMethod == "none":
		return "", "", false, false, ErrInvalidClientConfig
	}

	requirePKCE := true
	if input.RequirePKCE != nil {
		requirePKCE = *input.RequirePKCE
	}
	if clientType == "public" && !requirePKCE {
		return "", "", false, false, ErrInvalidClientConfig
	}

	requireConsent := true
	if input.RequireConsent != nil {
		requireConsent = *input.RequireConsent
	}

	return clientType, authMethod, requirePKCE, requireConsent, nil
}

func (s *Service) normalizeClientSecret(clientType, authMethod, secret string) (string, error) {
	if clientType == "public" || authMethod == "none" {
		if secret != "" {
			return "", ErrInvalidClientSecret
		}
		return "", nil
	}

	if len(secret) < 8 || len(secret) > 128 {
		return "", ErrInvalidClientSecret
	}
	if s.passwords == nil {
		return "", ErrInvalidClientSecret
	}

	hash, err := s.passwords.HashPassword(secret)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func normalizeGrantTypes(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, ErrInvalidGrantType
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		grantType := strings.ToLower(strings.TrimSpace(value))
		if grantType == "" {
			continue
		}
		if !slices.Contains(supportedGrantTypes, grantType) {
			return nil, ErrInvalidGrantType
		}
		if _, ok := seen[grantType]; ok {
			continue
		}
		seen[grantType] = struct{}{}
		result = append(result, grantType)
	}

	if len(result) == 0 {
		return nil, ErrInvalidGrantType
	}
	if containsString(result, "refresh_token") && !containsString(result, "authorization_code") {
		return nil, ErrInvalidClientConfig
	}

	return result, nil
}

func normalizeScopes(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, ErrInvalidScope
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		scope := strings.TrimSpace(value)
		if scope == "" {
			continue
		}
		if len(scope) > 128 {
			return nil, ErrInvalidScope
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}

	if len(result) == 0 {
		return nil, ErrInvalidScope
	}
	return result, nil
}

func normalizeClientRedirectURIs(values, grantTypes []string) ([]string, error) {
	if !containsString(grantTypes, "authorization_code") {
		return nil, nil
	}
	return normalizeRedirectURIs(values)
}

func normalizeRedirectURIs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, ErrRedirectURIRequired
	}

	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		redirectURI := strings.TrimSpace(value)
		if redirectURI == "" {
			continue
		}
		if len(redirectURI) > 1024 {
			return nil, ErrInvalidRedirectURI
		}
		if strings.Contains(redirectURI, "#") {
			return nil, ErrInvalidRedirectURI
		}

		parsed, err := url.ParseRequestURI(redirectURI)
		if err != nil || parsed.Scheme == "" || parsed.Fragment != "" {
			return nil, ErrInvalidRedirectURI
		}

		if _, ok := seen[redirectURI]; ok {
			continue
		}
		seen[redirectURI] = struct{}{}
		result = append(result, redirectURI)
	}

	if len(result) == 0 {
		return nil, ErrRedirectURIRequired
	}

	return result, nil
}

func normalizeOptionalRedirectURIs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	return normalizeRedirectURIs(values)
}

func normalizeTTL(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func normalizeRefreshTTL(value int, grantTypes []string) int {
	if !containsString(grantTypes, "refresh_token") {
		return 0
	}
	if value <= 0 {
		return 2592000
	}
	return value
}

func normalizeIDTokenTTL(value int, grantTypes []string) int {
	if !containsString(grantTypes, "authorization_code") {
		return 0
	}
	if value <= 0 {
		return 3600
	}
	return value
}

func normalizeStatus(value string) string {
	status := strings.ToLower(strings.TrimSpace(value))
	if status == "" {
		return "active"
	}
	return status
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
