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

// Service 提供 OIDC 相关的对外能力：
// userinfo、discovery、JWKS 以及 token introspection。
// 它本身不签发 token，而是站在“消费/验证 token”的角度对外暴露标准端点。
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
	// userinfo 先验证 access token，再根据 sub 反查本地用户资料。
	// 这样返回的数据始终以服务端当前状态为准，而不是完全依赖 token 内快照。
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
	// Discovery 文档把当前服务支持的 OIDC/OAuth 能力一次性声明出来，
	// 方便客户端自动发现端点和支持的认证方式。
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
	// 如果没有注入密钥提供方，返回空集合而不是报错，
	// 这样开发环境或部分测试场景也能保持接口形态稳定。
	if s.keys == nil {
		return &JSONWebKeySet{}, nil
	}
	return &JSONWebKeySet{Keys: s.keys.PublicJWKS()}, nil
}

func (s *Service) Introspect(ctx context.Context, input IntrospectionInput) (*IntrospectionOutput, error) {
	// introspection 的目标不是“重新签名验证一次就算有效”，
	// 而是同时确认：
	// 1. token 格式和签名有效；
	// 2. token 未被撤销；
	// 3. token 确实是本服务曾经签发并仍处于活动状态的 access token。
	token := strings.TrimSpace(input.AccessToken)
	if token == "" {
		return &IntrospectionOutput{Active: false}, nil
	}

	tokenSHA256 := sha256Hex(token)
	if s.tokenCache != nil {
		// 先查撤销缓存，可以在不命中数据库的情况下快速否定已失效 token。
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
	// 只信任“签名正确且在本地有发行记录”的 token。
	// 这一步可以拦住外部系统伪造的、但恰好使用相同签名规则的 JWT。
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
	// 先走缓存命中，再回退数据库。
	// 这是 introspection 高频路径上的一个典型“冷热分层”读取。
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
	// claim 解码来自 JWT，类型可能不完全可靠，这里统一做安全转换。
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
	// aud / scp 这类 claim 可能被编码成 string、[]string 或 []any，
	// 这里统一整理成 []string 供上层使用。
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
