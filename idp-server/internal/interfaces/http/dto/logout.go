package dto

// LogoutRequest 是普通退出和退出全部设备等动作共用的简化请求体。
type LogoutRequest struct {
	ReturnTo  string `json:"return_to" form:"return_to"`
	CSRFToken string `json:"csrf_token" form:"csrf_token"`
}
