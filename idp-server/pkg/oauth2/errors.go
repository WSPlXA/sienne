package oauth2

// Error 对应 OAuth2 规范定义的错误响应结构。
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}
