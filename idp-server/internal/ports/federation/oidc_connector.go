package federation

import "context"

// OIDCAuthenticateInput 是本地认证层传给联邦 OIDC 连接器的标准输入。
// 它同时覆盖“发起跳转”和“回调完成”两个阶段所需的数据。
type OIDCAuthenticateInput struct {
	RedirectURI string
	ReturnTo    string
	State       string
	Code        string
	Nonce       string
}

// OIDCAuthenticateResult 是联邦登录完成后的统一输出。
// 未完成第一跳时也可能只带 RedirectURI 而不带主体信息。
type OIDCAuthenticateResult struct {
	Authenticated bool
	Subject       string
	Username      string
	DisplayName   string
	Email         string
	RedirectURI   string
}

// OIDCConnector 抽象任意一个外部 OIDC IdP 连接器。
type OIDCConnector interface {
	Authenticate(ctx context.Context, input OIDCAuthenticateInput) (*OIDCAuthenticateResult, error)
}
