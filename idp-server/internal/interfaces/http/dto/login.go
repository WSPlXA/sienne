package dto

// LoginRequest 是登录页/登录接口接收的统一请求体。
// 它同时覆盖本地密码登录、联邦 OIDC 回调以及登录后回跳上下文。
type LoginRequest struct {
	Method      string `json:"method" form:"method"`
	Username    string `json:"username" form:"username"`
	Password    string `json:"password" form:"password"`
	CSRFToken   string `json:"csrf_token" form:"csrf_token"`
	ReturnTo    string `json:"return_to" form:"return_to"`
	RedirectURI string `json:"redirect_uri" form:"redirect_uri"`
	State       string `json:"state" form:"state"`
	Code        string `json:"code" form:"code"`
	Nonce       string `json:"nonce" form:"nonce"`
}
