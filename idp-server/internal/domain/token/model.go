package token

import "time"

// Model 是面向 HTTP token 响应的轻量 DTO，
// 区别于下面两个更偏持久化的 AccessToken / RefreshToken 实体。
type Model struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
}

// AccessToken 表示一条已签发 access token 的持久化记录。
type AccessToken struct {
	ID           int64
	TokenValue   string
	TokenSHA256  string
	ClientID     int64
	UserID       *int64
	Subject      string
	AudienceJSON string
	ScopesJSON   string
	TokenType    string
	TokenFormat  string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	CreatedAt    time.Time
}

// RefreshToken 表示一条可轮换、可撤销的 refresh token 记录。
// ReplacedByTokenID 用来把轮换链条串起来。
type RefreshToken struct {
	ID                int64
	TokenValue        string
	TokenSHA256       string
	ClientID          int64
	UserID            *int64
	Subject           string
	ScopesJSON        string
	IssuedAt          time.Time
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	ReplacedByTokenID *int64
	CreatedAt         time.Time
}
