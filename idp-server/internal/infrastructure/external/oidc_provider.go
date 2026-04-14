package external

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/federation"

	"github.com/google/uuid"
)

type OIDCProviderConfig struct {
	Issuer           string
	ClientID         string
	ClientSecret     string
	RedirectURI      string
	Scopes           []string
	ClientAuthMethod string
	UsernameClaim    string
	DisplayNameClaim string
	EmailClaim       string
	StateTTL         time.Duration
}

// OIDCProvider 封装与上游 OIDC 身份提供者的交互：
// 拉 discovery、发起授权、交换 code、获取 userinfo，并做最基本的 claim 校验。
type OIDCProvider struct {
	cfg         OIDCProviderConfig
	httpClient  *http.Client
	replayCache cacheport.ReplayProtectionRepository

	mu       sync.RWMutex
	metadata *oidcDiscoveryDocument
}

type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

func NewOIDCProvider(cfg OIDCProviderConfig) *OIDCProvider {
	return NewOIDCProviderWithReplayCache(cfg, nil)
}

func NewOIDCProviderWithReplayCache(cfg OIDCProviderConfig, replayCache cacheport.ReplayProtectionRepository) *OIDCProvider {
	// 配置在这里做一次标准化，保证后续请求路径不需要反复兜底默认值。
	scopes := normalizeScopes(cfg.Scopes)
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	stateTTL := cfg.StateTTL
	if stateTTL <= 0 {
		stateTTL = 10 * time.Minute
	}

	return &OIDCProvider{
		cfg: OIDCProviderConfig{
			Issuer:           strings.TrimSpace(cfg.Issuer),
			ClientID:         strings.TrimSpace(cfg.ClientID),
			ClientSecret:     cfg.ClientSecret,
			RedirectURI:      strings.TrimSpace(cfg.RedirectURI),
			Scopes:           scopes,
			ClientAuthMethod: normalizeClientAuthMethod(cfg.ClientAuthMethod),
			UsernameClaim:    fallback(cfg.UsernameClaim, "preferred_username"),
			DisplayNameClaim: fallback(cfg.DisplayNameClaim, "name"),
			EmailClaim:       fallback(cfg.EmailClaim, "email"),
			StateTTL:         stateTTL,
		},
		httpClient:  &http.Client{Timeout: 10 * time.Second},
		replayCache: replayCache,
	}
}

func (p *OIDCProvider) Authenticate(ctx context.Context, input federation.OIDCAuthenticateInput) (*federation.OIDCAuthenticateResult, error) {
	// Authenticate 同时承载联邦登录的两段流程：
	// 没有 code 时发起跳转，有 code 时完成回调兑换。
	if strings.TrimSpace(p.cfg.Issuer) == "" || strings.TrimSpace(p.cfg.ClientID) == "" {
		return nil, fmt.Errorf("oidc provider is not configured")
	}

	redirectURI := strings.TrimSpace(input.RedirectURI)
	if redirectURI == "" {
		redirectURI = p.cfg.RedirectURI
	}
	if redirectURI == "" {
		return nil, fmt.Errorf("oidc redirect_uri is required")
	}

	metadata, err := p.loadDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Code) == "" {
		return p.beginAuthentication(ctx, metadata, redirectURI, input.ReturnTo)
	}

	return p.completeAuthentication(ctx, metadata, input, redirectURI)
}

func (p *OIDCProvider) beginAuthentication(ctx context.Context, metadata *oidcDiscoveryDocument, redirectURI, returnTo string) (*federation.OIDCAuthenticateResult, error) {
	// state/nonce 都会先放进重放保护缓存里，
	// 回调时必须消费这份状态，避免 CSRF 和旧回调重放。
	if p.replayCache == nil {
		return nil, fmt.Errorf("oidc replay cache is not configured")
	}
	if metadata == nil || metadata.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("oidc discovery is missing authorization_endpoint")
	}

	state := uuid.NewString()
	nonce := uuid.NewString()
	if err := p.replayCache.SaveState(ctx, state, map[string]string{
		"nonce":        nonce,
		"return_to":    strings.TrimSpace(returnTo),
		"redirect_uri": redirectURI,
		"created_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}, p.cfg.StateTTL); err != nil {
		return nil, fmt.Errorf("save oidc state: %w", err)
	}

	authURL, err := buildAuthorizationURL(metadata.AuthorizationEndpoint, p.cfg.ClientID, redirectURI, state, nonce, p.cfg.Scopes)
	if err != nil {
		return nil, err
	}

	return &federation.OIDCAuthenticateResult{
		Authenticated: false,
		RedirectURI:   authURL,
	}, nil
}

func (p *OIDCProvider) completeAuthentication(ctx context.Context, metadata *oidcDiscoveryDocument, input federation.OIDCAuthenticateInput, redirectURI string) (*federation.OIDCAuthenticateResult, error) {
	// 回调阶段先消费 state，再用 code 交换 token，最后提取并校验用户 claims。
	savedState, err := p.consumeState(ctx, strings.TrimSpace(input.State))
	if err != nil {
		return nil, err
	}
	if value := strings.TrimSpace(savedState["redirect_uri"]); value != "" {
		redirectURI = value
	}
	nonce := strings.TrimSpace(savedState["nonce"])
	if input.Nonce != "" {
		nonce = strings.TrimSpace(input.Nonce)
	}

	tokenResponse, err := p.exchangeCode(ctx, metadata, input.Code, redirectURI)
	if err != nil {
		return nil, err
	}
	claims := map[string]any(nil)
	if metadata.UserInfoEndpoint != "" && tokenResponse.AccessToken != "" {
		claims, err = p.fetchUserInfo(ctx, metadata.UserInfoEndpoint, tokenResponse.AccessToken)
		if err != nil {
			return nil, err
		}
	}
	if len(claims) == 0 && tokenResponse.IDToken != "" {
		claims, err = decodeJWTClaims(tokenResponse.IDToken)
		if err != nil {
			return nil, err
		}
	}
	if len(claims) == 0 {
		return nil, fmt.Errorf("oidc provider returned no user claims")
	}
	issuer := p.cfg.Issuer
	if strings.TrimSpace(metadata.Issuer) != "" {
		issuer = strings.TrimSpace(metadata.Issuer)
	}
	if err := validateOIDCClaims(claims, issuer, p.cfg.ClientID, nonce); err != nil {
		return nil, err
	}

	subject := firstStringClaim(claims, "sub")
	if subject == "" {
		subject = firstStringClaim(claims, p.cfg.EmailClaim, p.cfg.UsernameClaim)
	}
	if subject == "" {
		return nil, fmt.Errorf("oidc subject claim is missing")
	}

	return &federation.OIDCAuthenticateResult{
		Authenticated: true,
		Subject:       subject,
		Username:      firstStringClaim(claims, p.cfg.UsernameClaim, "preferred_username", "name"),
		DisplayName:   firstStringClaim(claims, p.cfg.DisplayNameClaim, "name"),
		Email:         firstStringClaim(claims, p.cfg.EmailClaim, "email"),
		RedirectURI:   strings.TrimSpace(savedState["return_to"]),
	}, nil
}

func (p *OIDCProvider) loadDiscovery(ctx context.Context) (*oidcDiscoveryDocument, error) {
	// discovery 文档会缓存在内存里，避免每次联邦登录都重新拉取上游元数据。
	p.mu.RLock()
	if p.metadata != nil {
		defer p.mu.RUnlock()
		return p.metadata, nil
	}
	p.mu.RUnlock()

	discoveryURL := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build oidc discovery request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oidc discovery request returned %s", resp.Status)
	}

	var metadata oidcDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decode oidc discovery response: %w", err)
	}
	if metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("oidc discovery is missing token_endpoint")
	}

	p.mu.Lock()
	p.metadata = &metadata
	p.mu.Unlock()

	return &metadata, nil
}

func (p *OIDCProvider) exchangeCode(ctx context.Context, metadata *oidcDiscoveryDocument, code, redirectURI string) (*oidcTokenResponse, error) {
	// 这里按配置选择 client_secret_post 或 client_secret_basic 与上游 token endpoint 交互。
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.cfg.ClientID)
	if p.cfg.ClientAuthMethod == "client_secret_post" && p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, metadata.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build oidc token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.cfg.ClientAuthMethod == "client_secret_basic" && p.cfg.ClientSecret != "" {
		req.SetBasicAuth(p.cfg.ClientID, p.cfg.ClientSecret)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("oidc token request returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var tokenResponse oidcTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("decode oidc token response: %w", err)
	}
	if tokenResponse.AccessToken == "" && tokenResponse.IDToken == "" {
		return nil, fmt.Errorf("oidc token response is missing tokens")
	}

	return &tokenResponse, nil
}

func (p *OIDCProvider) fetchUserInfo(ctx context.Context, endpoint, accessToken string) (map[string]any, error) {
	// 如果上游提供 userinfo endpoint，优先从那里拿最新用户信息；
	// 否则再退回到 ID Token 内的 claims。
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build oidc userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("oidc userinfo request returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decode oidc userinfo response: %w", err)
	}
	return claims, nil
}

func decodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid id_token format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode id_token payload: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("decode id_token claims: %w", err)
	}
	return claims, nil
}

func validateOIDCClaims(claims map[string]any, issuer, audience, nonce string) error {
	if issuer != "" {
		if got := firstStringClaim(claims, "iss"); got != "" && got != issuer {
			return fmt.Errorf("unexpected oidc issuer")
		}
	}
	if audience != "" {
		if rawAud, ok := claims["aud"]; ok && !claimContainsAudience(rawAud, audience) {
			return fmt.Errorf("unexpected oidc audience")
		}
	}
	if nonce != "" {
		if got := firstStringClaim(claims, "nonce"); got != "" && got != nonce {
			return fmt.Errorf("unexpected oidc nonce")
		}
	}
	return nil
}

func claimContainsAudience(raw any, expected string) bool {
	switch aud := raw.(type) {
	case string:
		return aud == expected
	case []any:
		for _, item := range aud {
			if value, ok := item.(string); ok && value == expected {
				return true
			}
		}
	}
	return false
}

func firstStringClaim(claims map[string]any, keys ...string) string {
	for _, key := range keys {
		value, _ := claims[key].(string)
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func normalizeClientAuthMethod(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "client_secret_basic":
		return "client_secret_basic"
	case "client_secret_post", "none":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "client_secret_basic"
	}
}

func fallback(value, defaultValue string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return defaultValue
	}
	return trimmed
}

func (p *OIDCProvider) consumeState(ctx context.Context, state string) (map[string]string, error) {
	if state == "" {
		return nil, fmt.Errorf("oidc state is required")
	}
	if p.replayCache == nil {
		return nil, fmt.Errorf("oidc replay cache is not configured")
	}

	value, err := p.replayCache.GetState(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("load oidc state: %w", err)
	}
	if value == nil {
		return nil, fmt.Errorf("oidc state is invalid or expired")
	}
	if err := p.replayCache.DeleteState(ctx, state); err != nil {
		return nil, fmt.Errorf("delete oidc state: %w", err)
	}
	return value, nil
}

func buildAuthorizationURL(endpoint, clientID, redirectURI, state, nonce string, scopes []string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("build oidc authorization url: %w", err)
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func normalizeScopes(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
