package plugin

import (
	"context"

	userdomain "idp-server/internal/domain/user"
)

// AuthnMethodType 是登录方式插件的稳定标识。
// 应用层通过这个枚举选择认证策略，而不是直接依赖具体实现类型。
type AuthnMethodType string

const (
	AuthnMethodTypePassword      AuthnMethodType = "password"
	AuthnMethodTypeFederatedOIDC AuthnMethodType = "federated_oidc"
)

type AuthenticateInput struct {
	// Username / Password 主要服务于本地密码登录；
	// RedirectURI / State / Code / Nonce 则用于联邦登录等需要浏览器往返的场景。
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
	// Handled 表示该插件是否真正接管了这次认证请求；
	// 对某些插件来说，第一次调用可能只返回一个跳转地址而不是最终认证成功。
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

// AuthnMethod 定义了“一个可插拔登录方式”最小需要提供的能力。
type AuthnMethod interface {
	Name() string
	Type() AuthnMethodType
	Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error)
}
