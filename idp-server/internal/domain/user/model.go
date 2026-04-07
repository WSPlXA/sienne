package user

import "time"

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
