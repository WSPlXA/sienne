package totp

import "time"

// Model 表示用户已绑定的一份 TOTP 凭据。
// Secret 通常会在持久化层被加密存储，这里保留的是领域层语义。
type Model struct {
	ID        int64
	UserID    int64
	Secret    string
	EnabledAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}
