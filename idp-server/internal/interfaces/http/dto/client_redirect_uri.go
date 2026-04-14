package dto

// RegisterClientRedirectURIRequest 用于后台给既有 client 追加或覆盖回调地址。
// 同时保留单个和批量字段，是为了兼容表单页面与脚本化 API 两种调用方式。
type RegisterClientRedirectURIRequest struct {
	RedirectURI  string   `json:"redirect_uri" form:"redirect_uri"`
	RedirectURIs []string `json:"redirect_uris" form:"redirect_uris"`
}
