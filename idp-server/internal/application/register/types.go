package register

import (
	"errors"
	"time"
)

var (
	ErrInvalidUsername      = errors.New("invalid username")
	ErrInvalidEmail         = errors.New("invalid email")
	ErrInvalidDisplayName   = errors.New("invalid display name")
	ErrWeakPassword         = errors.New("password does not meet policy")
	ErrUsernameAlreadyUsed  = errors.New("username already exists")
	ErrEmailAlreadyUsed     = errors.New("email already exists")
	ErrUserNotFound         = errors.New("user not found")
	ErrPasswordUpdateFailed = errors.New("password update is not supported by repository")
	ErrUserUnlockFailed     = errors.New("user unlock is not supported by repository")
)

// RegisterInput 是创建本地用户时需要的最小输入集合。
type RegisterInput struct {
	Username      string
	Email         string
	DisplayName   string
	Password      string
	EmailVerified bool
	AutoActivate  bool
}

// RegisterResult 返回新建用户的核心公开字段，不暴露密码相关信息。
type RegisterResult struct {
	UserID        int64
	UserUUID      string
	Username      string
	Email         string
	EmailVerified bool
	DisplayName   string
	Status        string
	CreatedAt     time.Time
}

// AdminResetPasswordInput / Result 表示后台重置用户密码动作的输入输出。
type AdminResetPasswordInput struct {
	UserID      int64
	NewPassword string
}

type AdminResetPasswordResult struct {
	UserID        int64
	Username      string
	PasswordSetAt time.Time
}

// AdminUnlockUserInput / Result 表示后台解锁用户账号动作的输入输出。
type AdminUnlockUserInput struct {
	UserID int64
}

type AdminUnlockUserResult struct {
	UserID     int64
	Username   string
	UnlockedAt time.Time
}
