package plugin

import (
	"context"

	clientdomain "idp-server/internal/domain/client"
)

// ClientAuthMethodType 对应 OAuth2 token endpoint 常见的 client authentication 方法。
type ClientAuthMethodType string

const (
	ClientAuthMethodClientSecretBasic ClientAuthMethodType = "client_secret_basic"
	ClientAuthMethodClientSecretPost  ClientAuthMethodType = "client_secret_post"
	ClientAuthMethodNone              ClientAuthMethodType = "none"
)

type ClientAuthenticateInput struct {
	// Client 是服务端已加载的客户端配置，
	// 其余字段是本次 HTTP 请求带来的认证材料。
	Client              *clientdomain.Model
	AuthorizationHeader string
	ClientID            string
	ClientSecret        string
}

type ClientAuthenticateResult struct {
	// 返回里既包含确认后的 client_id，也带上最终采用的方法，便于上层审计和后续分支。
	ClientID     string
	ClientSecret string
	Method       ClientAuthMethodType
}

// ClientAuthenticator 定义一种具体 client auth 方法的校验接口。
type ClientAuthenticator interface {
	Name() string
	Type() ClientAuthMethodType
	Authenticate(ctx context.Context, input ClientAuthenticateInput) (*ClientAuthenticateResult, error)
}
