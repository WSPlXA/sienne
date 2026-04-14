package authz

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	authorizationdomain "idp-server/internal/domain/authorization"
	"idp-server/internal/ports/repository"
	pkgoauth2 "idp-server/pkg/oauth2"

	"github.com/google/uuid"
)

type Service interface {
	Authorize(ctx context.Context, cmd *AuthorizationCommand) (*AuthorizationResult, error)
}

// AuthorizationService 负责 OAuth2 Authorization Code 流程中的“前半段”：
// 在用户已登录的前提下校验客户端、scope、PKCE 和 consent，
// 然后签发一个短生命周期的 authorization code 交给前端回跳。
type AuthorizationService struct {
	clients   repository.ClientRepository
	sessions  repository.SessionRepository
	codes     repository.AuthorizationCodeRepository
	consents  repository.ConsentRepository
	codeTTL   time.Duration
	now       func() time.Time
	codeMaker func() string
}

func NewService(
	clients repository.ClientRepository,
	sessions repository.SessionRepository,
	codes repository.AuthorizationCodeRepository,
	consents repository.ConsentRepository,
	codeTTL time.Duration,
) *AuthorizationService {
	return &AuthorizationService{
		clients:  clients,
		sessions: sessions,
		codes:    codes,
		consents: consents,
		codeTTL:  codeTTL,
		now: func() time.Time {
			return time.Now().UTC()
		},
		codeMaker: func() string {
			return uuid.NewString() + "." + uuid.NewString()
		},
	}
}

func (s *AuthorizationService) Authorize(ctx context.Context, cmd *AuthorizationCommand) (*AuthorizationResult, error) {
	// Authorize 不直接处理页面跳转，而是返回“下一步该做什么”的结果：
	// 要求登录、要求 consent，或者直接返回 code。
	if cmd == nil {
		return nil, ErrInvalidRequest
	}
	if strings.TrimSpace(cmd.ClientID) == "" || strings.TrimSpace(cmd.RedirectURI) == "" {
		return nil, ErrInvalidRequest
	}
	if pkgoauth2.ResponseType(strings.TrimSpace(cmd.ResponseType)) != pkgoauth2.ResponseType("code") {
		return nil, ErrUnsupportedResponseType
	}

	client, err := s.clients.FindByClientID(ctx, strings.TrimSpace(cmd.ClientID))
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" {
		return nil, ErrInvalidClient
	}
	if !contains(client.GrantTypes, string(pkgoauth2.GrantTypeAuthorizationCode)) {
		return nil, ErrInvalidClient
	}
	if !contains(client.RedirectURIs, cmd.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}

	// scope 先规范化去重，再和客户端允许的 scope 交叉校验。
	// 如果调用方一个 scope 都没传，这里默认回退到 openid，保持 OIDC 登录可用。
	scopes := normalizeScopes(cmd.Scope)
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	if !allContained(scopes, client.Scopes) {
		return nil, ErrInvalidScope
	}
	if err := validatePKCE(client.RequirePKCE, strings.TrimSpace(cmd.CodeChallenge), strings.TrimSpace(cmd.CodeChallengeMethod)); err != nil {
		return nil, err
	}

	sessionID := strings.TrimSpace(cmd.SessionID)
	if sessionID == "" {
		// authorize 端点本身不创建会话；如果当前请求没有登录态，
		// 就把控制权交回上层，让浏览器先去登录。
		return &AuthorizationResult{
			RequireLogin:     true,
			LoginRedirectURI: "/login",
		}, nil
	}

	currentSession, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if currentSession == nil || currentSession.LoggedOutAt != nil || !currentSession.ExpiresAt.After(s.now()) {
		return &AuthorizationResult{
			RequireLogin:     true,
			LoginRedirectURI: "/login",
		}, nil
	}

	if client.RequireConsent && s.consents != nil {
		// client 开启 require_consent 时，只有用户对当前 scope 集合已有有效授权，
		// 才能直接发 code；否则必须先经过 consent 页面确认。
		hasConsent, err := s.consents.HasActiveConsent(ctx, currentSession.UserID, client.ID, scopes)
		if err != nil {
			return nil, err
		}
		if !hasConsent {
			return &AuthorizationResult{
				RequireConsent:     true,
				ConsentRedirectURI: "/consent",
			}, nil
		}
	}

	now := s.now()
	scopeJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, err
	}

	sessionDBID := currentSession.ID
	// authorization code 本质上是一个短命“兑换凭证”：
	// 它绑定 client、user、redirect_uri、scope、nonce 和 PKCE 元数据，
	// 后续 token 端点会用这些字段做二次核验。
	codeModel := &authorizationdomain.Model{
		Code:                s.codeMaker(),
		ClientDBID:          client.ID,
		UserID:              currentSession.UserID,
		SessionDBID:         &sessionDBID,
		RedirectURI:         cmd.RedirectURI,
		ScopesJSON:          string(scopeJSON),
		StateValue:          strings.TrimSpace(cmd.State),
		NonceValue:          strings.TrimSpace(cmd.Nonce),
		CodeChallenge:       strings.TrimSpace(cmd.CodeChallenge),
		CodeChallengeMethod: normalizeCodeChallengeMethod(cmd.CodeChallengeMethod),
		ExpiresAt:           now.Add(s.codeTTL),
	}
	if err := s.codes.Create(ctx, codeModel); err != nil {
		return nil, err
	}

	return &AuthorizationResult{
		RedirectURI: cmd.RedirectURI,
		Code:        codeModel.Code,
		State:       cmd.State,
	}, nil
}

func normalizeScopes(scopes []string) []string {
	// scope 的顺序保留、重复项去掉，方便后续既可比对也可回显。
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}

func allContained(values, allowed []string) bool {
	// 用 set 做包含判断，避免 scope 校验时出现 O(n^2) 的重复扫描。
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		allowedSet[value] = struct{}{}
	}

	for _, value := range values {
		if _, ok := allowedSet[value]; !ok {
			return false
		}
	}
	return true
}

func validatePKCE(requirePKCE bool, challenge, method string) error {
	// 如果客户端要求 PKCE，就必须带 challenge；
	// method 目前仅接受 plain 和 S256 两种标准方式。
	if challenge == "" {
		if requirePKCE {
			return ErrInvalidCodeChallenge
		}
		return nil
	}

	switch normalizeCodeChallengeMethod(method) {
	case "plain", "S256":
		return nil
	default:
		return ErrInvalidCodeChallenge
	}
}

func normalizeCodeChallengeMethod(method string) string {
	// 统一把空值和大小写差异折叠成固定写法，简化后续持久化和比较逻辑。
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", "PLAIN":
		return "plain"
	case "S256":
		return "S256"
	default:
		return strings.TrimSpace(method)
	}
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
