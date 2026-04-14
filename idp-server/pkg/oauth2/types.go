package oauth2

// 这些类型把 OAuth2 协议里的若干字符串字面量收敛成更明确的领域别名。
type GrantType string
type ResponseType string
type TokenType string
type ClientAuthMethod string
type CodeChallengeMethod string

// TokenResponse 对应标准 token endpoint 成功响应体。
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}
