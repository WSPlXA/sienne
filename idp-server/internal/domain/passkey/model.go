package passkey

import "time"

// Model 表示一条已注册的 Passkey/WebAuthn 凭据记录。
// CredentialJSON 存的是库可直接反序列化使用的原始 credential 结构。
type Model struct {
	ID             int64
	UserID         int64
	CredentialID   string
	CredentialJSON string
	LastUsedAt     *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
