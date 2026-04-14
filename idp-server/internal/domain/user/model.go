package user

import "time"

// Model 表示系统中的本地用户实体。
// 它同时承载登录身份、展示资料和部分后台权限信息，因此会被认证、授权和管理后台多处复用。
type Model struct {
	ID               int64
	UserUUID         string
	Username         string
	Email            string
	EmailVerified    bool
	DisplayName      string
	PasswordHash     string
	RoleCode         string
	PrivilegeMask    uint32
	TenantScope      string
	Status           string
	FailedLoginCount int
	LastLoginAt      *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}
