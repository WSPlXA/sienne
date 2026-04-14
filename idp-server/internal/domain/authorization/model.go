package authorization

import "time"

// Model 表示一条待兑换的 authorization code 记录。
// 它把授权请求上下文（client、user、redirect_uri、scope、PKCE、nonce）一起冻结下来，
// 供 token endpoint 在兑换时做完整二次校验。
type Model struct {
	ID                  int64
	Code                string
	ClientDBID          int64
	UserID              int64
	SessionDBID         *int64
	RedirectURI         string
	ScopesJSON          string
	StateValue          string
	NonceValue          string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	ConsumedAt          *time.Time
	CreatedAt           time.Time
}
