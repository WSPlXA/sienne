package dto

import "strings"

// AuthorizeRequest 对应 `/oauth2/authorize` 的查询参数视图。
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" json:"response_type" binding:"required"`
	ClientID            string `form:"client_id" json:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" json:"redirect_uri" binding:"required"`
	Scope               string `form:"scope" json:"scope"`
	State               string `form:"state" json:"state"`
	Nonce               string `form:"nonce" json:"nonce"`
	CodeChallenge       string `form:"code_challenge" json:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method" json:"code_challenge_method"`
}

func (r AuthorizeRequest) ScopeList() []string {
	// authorize 请求里的 scope 同样采用空格分隔表示。
	if strings.TrimSpace(r.Scope) == "" {
		return nil
	}
	return strings.Fields(r.Scope)
}
