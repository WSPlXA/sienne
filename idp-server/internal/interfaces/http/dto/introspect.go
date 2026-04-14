package dto

import (
	"fmt"
	"strings"
)

// IntrospectRequest 对应 token introspection endpoint 的输入结构。
type IntrospectRequest struct {
	Token         string `form:"token" json:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint"`
	ClientID      string `form:"client_id" json:"client_id"`
	ClientSecret  string `form:"client_secret" json:"client_secret"`
}

func (r IntrospectRequest) Validate() error {
	// 这里只检查最基本的 token 存在性；
	// token_type_hint 目前作为可选提示字段保留。
	if strings.TrimSpace(r.Token) == "" {
		return fmt.Errorf("token is required")
	}
	return nil
}
