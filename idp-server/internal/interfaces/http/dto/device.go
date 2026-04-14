package dto

// DeviceAuthorizeRequest 是 device authorization endpoint 的输入结构。
type DeviceAuthorizeRequest struct {
	ClientID     string `form:"client_id" json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
	Scope        string `form:"scope" json:"scope"`
}

func (r DeviceAuthorizeRequest) ScopeList() []string {
	return TokenRequest{Scope: r.Scope}.ScopeList()
}

// DeviceVerifyRequest 是浏览器端 device verification 页提交的输入结构。
type DeviceVerifyRequest struct {
	UserCode  string `form:"user_code" json:"user_code"`
	Action    string `form:"action" json:"action"`
	CSRFToken string `form:"csrf_token" json:"csrf_token"`
}
