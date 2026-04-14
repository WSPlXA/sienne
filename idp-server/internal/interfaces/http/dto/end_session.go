package dto

// EndSessionRequest 对应 OIDC RP-Initiated Logout 请求参数。
type EndSessionRequest struct {
	ClientID              string `json:"client_id" form:"client_id"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri" form:"post_logout_redirect_uri"`
	State                 string `json:"state" form:"state"`
	CSRFToken             string `json:"csrf_token" form:"csrf_token"`
}
