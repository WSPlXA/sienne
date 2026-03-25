package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
)

type tokenValidator interface {
	ParseAndValidate(token string, opts any) (map[string]any, error)
}

type jwtValidator interface {
	ParseAndValidate(token string, opts ValidateOptions) (map[string]any, error)
}

type ValidateOptions struct {
	Issuer string
}

type UserInfoProvider interface {
	GetUserInfo(ctx context.Context, input UserInfoInput) (*UserInfoOutput, error)
}

type MetadataProvider interface {
	Discovery(ctx context.Context) (*DiscoveryDocument, error)
	JWKS(ctx context.Context) (*JSONWebKeySet, error)
}

type IntrospectionProvider interface {
	Introspect(ctx context.Context, input IntrospectionInput) (*IntrospectionOutput, error)
}

type Service struct {
	users        repository.UserRepository
	accessTokens repository.TokenRepository
	tokenCache   cacheport.TokenCacheRepository
	tokens       jwtValidator
	keys         jwksProvider
	issuer       string
	now          func() time.Time
}

type jwksProvider interface {
	PublicJWKS() []JSONWebKey
}

func NewService(users repository.UserRepository, accessTokens repository.TokenRepository, tokenCache cacheport.TokenCacheRepository, tokens jwtValidator, keys jwksProvider, issuer string) *Service {
	return &Service{
		users:        users,
		accessTokens: accessTokens,
		tokenCache:   tokenCache,
		tokens:       tokens,
		keys:         keys,
		issuer:       issuer,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (s *Service) GetUserInfo(ctx context.Context, input UserInfoInput) (*UserInfoOutput, error) {
	if strings.TrimSpace(input.AccessToken) == "" {
		return nil, ErrInvalidAccessToken
	}

	claims, err := s.tokens.ParseAndValidate(input.AccessToken, ValidateOptions{
		Issuer: s.issuer,
	})
	if err != nil {
		return nil, ErrInvalidAccessToken
	}

	subject, _ := claims["sub"].(string)
	if subject == "" {
		return nil, ErrInvalidAccessToken
	}

	user, err := s.users.FindByUserUUID(ctx, subject)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	return &UserInfoOutput{
		Subject:       user.UserUUID,
		Name:          user.DisplayName,
		PreferredName: user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
	}, nil
}

func (s *Service) Discovery(ctx context.Context) (*DiscoveryDocument, error) {
	_ = ctx
	base := strings.TrimRight(s.issuer, "/")
	return &DiscoveryDocument{
		Issuer:                                    base,
		AuthorizationEndpoint:                     base + "/oauth2/authorize",
		TokenEndpoint:                             base + "/oauth2/token",
		UserInfoEndpoint:                          base + "/oauth2/userinfo",
		IntrospectionEndpoint:                     base + "/oauth2/introspect",
		EndSessionEndpoint:                        base + "/connect/logout",
		JWKSURI:                                   base + "/oauth2/jwks",
		ResponseTypesSupported:                    []string{"code"},
		SubjectTypesSupported:                     []string{"public"},
		IDTokenSigningAlgValuesSupported:          []string{"RS256"},
		ScopesSupported:                           []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethodsSupported:         []string{"client_secret_basic", "client_secret_post", "none"},
		IntrospectionEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		GrantTypesSupported:                       []string{"authorization_code", "refresh_token", "client_credentials"},
		CodeChallengeMethodsSupported:             []string{"plain", "S256"},
	}, nil
}

func (s *Service) JWKS(ctx context.Context) (*JSONWebKeySet, error) {
	_ = ctx
	if s.keys == nil {
		return &JSONWebKeySet{}, nil
	}
	return &JSONWebKeySet{Keys: s.keys.PublicJWKS()}, nil
}

func (s *Service) Introspect(ctx context.Context, input IntrospectionInput) (*IntrospectionOutput, error) {
	token := strings.TrimSpace(input.AccessToken)
	if token == "" {
		return &IntrospectionOutput{Active: false}, nil
	}

	tokenSHA256 := sha256Hex(token)
	if s.tokenCache != nil {
		revoked, err := s.tokenCache.IsAccessTokenRevoked(ctx, tokenSHA256)
		if err != nil {
			return nil, err
		}
		if revoked {
			return &IntrospectionOutput{Active: false}, nil
		}
	}

	claims, err := s.tokens.ParseAndValidate(token, ValidateOptions{
		Issuer: s.issuer,
	})
	if err != nil {
		return &IntrospectionOutput{Active: false}, nil
	}
	if !s.isServerIssuedAccessToken(ctx, tokenSHA256) {
		return &IntrospectionOutput{Active: false}, nil
	}

	result := &IntrospectionOutput{
		Active:    true,
		Scope:     strings.Join(claimStringSlice(claims["scp"]), " "),
		ClientID:  stringClaim(claims["cid"]),
		TokenType: "Bearer",
		Exp:       int64Claim(claims["exp"]),
		Iat:       int64Claim(claims["iat"]),
		Nbf:       int64Claim(claims["nbf"]),
		Sub:       stringClaim(claims["sub"]),
		Aud:       claimStringSlice(claims["aud"]),
		Iss:       stringClaim(claims["iss"]),
		Jti:       stringClaim(claims["jti"]),
	}

	if s.users != nil && result.Sub != "" {
		user, err := s.users.FindByUserUUID(ctx, result.Sub)
		if err != nil {
			return nil, err
		}
		if user != nil {
			result.Username = user.Username
			result.UpdatedAt = user.UpdatedAt
		}
	}

	return result, nil
}

func (s *Service) isServerIssuedAccessToken(ctx context.Context, tokenSHA256 string) bool {
	if s.tokenCache != nil {
		entry, err := s.tokenCache.GetAccessToken(ctx, tokenSHA256)
		if err == nil && entry != nil {
			return entry.ExpiresAt.After(s.now())
		}
	}
	if s.accessTokens == nil {
		return false
	}
	model, err := s.accessTokens.FindActiveAccessTokenBySHA256(ctx, tokenSHA256)
	return err == nil && model != nil
}

func stringClaim(value any) string {
	result, _ := value.(string)
	return strings.TrimSpace(result)
}

func int64Claim(value any) int64 {
	switch v := value.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	default:
		return 0
	}
}

func claimStringSlice(value any) []string {
	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{strings.TrimSpace(v)}
	case []string:
		result := make([]string, 0, len(v))
		for _, item := range v {
			item = strings.TrimSpace(item)
			if item != "" {
				result = append(result, item)
			}
		}
		return result
	case []any:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if text, ok := item.(string); ok {
				text = strings.TrimSpace(text)
				if text != "" {
					result = append(result, text)
				}
			}
		}
		return result
	default:
		return nil
	}
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
