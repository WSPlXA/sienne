package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"idp-server/internal/application/oidc"
	infracrypto "idp-server/internal/infrastructure/crypto"
	infraexternal "idp-server/internal/infrastructure/external"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	cacheport "idp-server/internal/ports/cache"
)

// App 是启动阶段产出的顶层运行对象。
// 当前只暴露 Router，因为这个二进制的唯一职责是提供 HTTP 服务；
// 如果未来需要优雅停机、后台任务或健康探针对象，也可以继续在这里扩展。
type App struct {
	Router http.Handler
}

// Wire 把“配置 -> 基础设施 -> 仓储 -> 应用服务 -> HTTP 接口”这条依赖链一次性串起来。
// 这个函数是整个进程的 Composition Root：只有这里知道具体实现类型，
// 其余层只依赖接口或更窄的抽象，便于测试和后续替换实现。
func Wire() (*App, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return initializeApp(ctx, cfg)
}

func buildFederatedOIDCProvider(cfg *config, replayCache cacheport.ReplayProtectionRepository) *infraexternal.OIDCProvider {
	if cfg == nil {
		return nil
	}
	if strings.TrimSpace(cfg.FederatedOIDCIssuer) == "" || strings.TrimSpace(cfg.FederatedOIDCClientID) == "" {
		return nil
	}

	return infraexternal.NewOIDCProviderWithReplayCache(infraexternal.OIDCProviderConfig{
		Issuer:           cfg.FederatedOIDCIssuer,
		ClientID:         cfg.FederatedOIDCClientID,
		ClientSecret:     cfg.FederatedOIDCClientSecret,
		RedirectURI:      cfg.FederatedOIDCRedirectURI,
		Scopes:           append([]string(nil), cfg.FederatedOIDCScopes...),
		ClientAuthMethod: cfg.FederatedOIDCClientAuthMethod,
		UsernameClaim:    cfg.FederatedOIDCUsernameClaim,
		DisplayNameClaim: cfg.FederatedOIDCDisplayNameClaim,
		EmailClaim:       cfg.FederatedOIDCEmailClaim,
		StateTTL:         cfg.FederatedOIDCStateTTL,
	}, replayCache)
}

func resolvePasskeyRPConfig(cfg *config) (string, string, []string, error) {
	if cfg == nil {
		return "", "", nil, fmt.Errorf("missing config")
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return "", "", nil, fmt.Errorf("missing issuer")
	}
	issuerURL, err := neturl.Parse(issuer)
	if err != nil {
		return "", "", nil, fmt.Errorf("parse issuer: %w", err)
	}
	if issuerURL.Scheme == "" || issuerURL.Host == "" {
		return "", "", nil, fmt.Errorf("invalid issuer origin")
	}

	rpID := strings.TrimSpace(cfg.PasskeyRPID)
	if rpID == "" {
		rpID = strings.TrimSpace(issuerURL.Hostname())
	}
	if rpID == "" {
		return "", "", nil, fmt.Errorf("missing passkey rp id")
	}

	origins := make([]string, 0, len(cfg.PasskeyRPOrigins)+1)
	for _, origin := range cfg.PasskeyRPOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		origins = append(origins, origin)
	}
	if len(origins) == 0 {
		origins = append(origins, issuerURL.Scheme+"://"+issuerURL.Host)
	}

	displayName := strings.TrimSpace(cfg.PasskeyRPDisplayName)
	if displayName == "" {
		displayName = "IDP Server"
	}

	return rpID, displayName, origins, nil
}

func resolveTOTPIssuer(cfg *config) string {
	if cfg == nil {
		return ""
	}
	display := strings.TrimSpace(cfg.TOTPIssuer)
	if display != "" {
		return display
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return ""
	}
	issuerURL, err := neturl.Parse(issuer)
	if err == nil {
		host := strings.TrimSpace(issuerURL.Hostname())
		if host != "" {
			return host
		}
	}
	return issuer
}

// jwtServiceAdapter和jwtMiddlewareAdapter是适配器结构体，用于将infracrypto.JWTService适配为应用程序中使用的JWT服务接口。这些适配器实现了相应的接口方法，并将调用委托给infracrypto.JWTService实例。
type jwtServiceAdapter struct {
	service *infracrypto.JWTService
}

func (a *jwtServiceAdapter) ParseAndValidate(token string, opts oidc.ValidateOptions) (map[string]any, error) {
	return a.service.ParseAndValidate(token, infracrypto.ValidateOptions{
		Issuer: opts.Issuer,
	})
}

type jwtMiddlewareAdapter struct {
	service *infracrypto.JWTService
}

func (a *jwtMiddlewareAdapter) ParseAndValidate(token string, opts httpmiddleware.ValidateOptions) (map[string]any, error) {
	return a.service.ParseAndValidate(token, infracrypto.ValidateOptions{
		Issuer: opts.Issuer,
	})
}

type keyManagerAdapter struct {
	manager *infracrypto.KeyManager
}

func (a keyManagerAdapter) PublicJWKS() []oidc.JSONWebKey {
	if a.manager == nil {
		return nil
	}

	keys := a.manager.PublicJWKS()
	result := make([]oidc.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		result = append(result, oidc.JSONWebKey{
			Kty: key.Kty,
			Kid: key.Kid,
			Use: key.Use,
			Alg: key.Alg,
			N:   key.N,
			E:   key.E,
		})
	}
	return result
}
