package dto

import (
	"fmt"
	"strings"
)

type IntrospectRequest struct {
	Token         string `form:"token" json:"token" binding:"required"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint"`
	ClientID      string `form:"client_id" json:"client_id"`
	ClientSecret  string `form:"client_secret" json:"client_secret"`
}

func (r IntrospectRequest) Validate() error {
	if strings.TrimSpace(r.Token) == "" {
		return fmt.Errorf("token is required")
	}
	return nil
}
