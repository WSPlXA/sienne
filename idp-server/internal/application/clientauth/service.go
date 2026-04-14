package clientauth

import (
	"context"
	"encoding/base64"
	"strings"

	apptoken "idp-server/internal/application/token"
	pluginregistry "idp-server/internal/plugins/registry"
	pluginport "idp-server/internal/ports/plugin"
	"idp-server/internal/ports/repository"
)

type Authenticator interface {
	Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error)
}

type AuthenticateInput struct {
	AuthorizationHeader string
	ClientID            string
	ClientSecret        string
}

type AuthenticateResult struct {
	ClientID     string
	ClientSecret string
	Method       pluginport.ClientAuthMethodType
}

// Service 负责 token/device/introspection 等端点上的 OAuth client 身份认证。
// 它的职责不是直接比较所有可能输入，而是：
// 1. 先定位 client；
// 2. 根据 client 配置选择认证方法；
// 3. 把具体校验委托给对应插件实现。
type Service struct {
	clients  repository.ClientRepository
	registry *pluginregistry.ClientAuthRegistry
}

func NewService(clients repository.ClientRepository, registry *pluginregistry.ClientAuthRegistry) *Service {
	return &Service{
		clients:  clients,
		registry: registry,
	}
}

func (s *Service) Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error) {
	// client 认证的第一步是先确定“请求声称自己是谁”。
	// 对 Basic 来说 client_id 在 Authorization 头里，对 post/none 来说则在 body 中。
	if s.clients == nil || s.registry == nil {
		return nil, apptoken.ErrInvalidClient
	}

	clientID := extractClientID(input.AuthorizationHeader, input.ClientID)
	if clientID == "" {
		return nil, apptoken.ErrInvalidClient
	}

	client, err := s.clients.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" {
		return nil, apptoken.ErrInvalidClient
	}

	// 真正采用哪种认证方式由 client 的注册配置决定，
	// 而不是由请求随意声明，从而避免认证方法被降级。
	methodType := normalizeClientAuthMethod(client.TokenEndpointAuthMethod, client.AuthMethods)
	authenticator, ok := s.registry.Get(methodType)
	if !ok || authenticator == nil {
		return nil, apptoken.ErrInvalidClient
	}

	result, err := authenticator.Authenticate(ctx, pluginport.ClientAuthenticateInput{
		Client:              client,
		AuthorizationHeader: input.AuthorizationHeader,
		ClientID:            input.ClientID,
		ClientSecret:        input.ClientSecret,
	})
	if err != nil {
		return nil, err
	}
	if result == nil || strings.TrimSpace(result.ClientID) == "" {
		return nil, apptoken.ErrInvalidClient
	}
	// 即使底层插件验签/验密成功，也要再次核对返回的 client_id 与已加载 client 一致。
	if result.ClientID != client.ClientID {
		return nil, apptoken.ErrInvalidClient
	}

	return &AuthenticateResult{
		ClientID:     result.ClientID,
		ClientSecret: result.ClientSecret,
		Method:       result.Method,
	}, nil
}

func extractClientID(authorizationHeader, bodyClientID string) string {
	// 为了先查 client 配置，这里先做一次“轻量提取 client_id”，
	// 真正的 secret 校验仍交给具体认证插件。
	if strings.HasPrefix(authorizationHeader, "Basic ") {
		payload := strings.TrimPrefix(authorizationHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[0])
			}
		}
	}

	return strings.TrimSpace(bodyClientID)
}

func normalizeClientAuthMethod(primary string, fallbacks []string) pluginport.ClientAuthMethodType {
	// 优先使用主配置字段，缺失时再回退到兼容性的 authMethods 列表。
	method := pluginport.ClientAuthMethodType(strings.ToLower(strings.TrimSpace(primary)))
	if method != "" {
		return method
	}
	for _, candidate := range fallbacks {
		method = pluginport.ClientAuthMethodType(strings.ToLower(strings.TrimSpace(candidate)))
		if method != "" {
			return method
		}
	}
	return pluginport.ClientAuthMethodNone
}
