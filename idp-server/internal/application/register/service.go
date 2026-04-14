package register

import (
	"context"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"

	userdomain "idp-server/internal/domain/user"
	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"

	"github.com/google/uuid"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{3,32}$`)

type Registrar interface {
	Register(ctx context.Context, input RegisterInput) (*RegisterResult, error)
}

type PasswordResetter interface {
	AdminResetPassword(ctx context.Context, input AdminResetPasswordInput) (*AdminResetPasswordResult, error)
}

type AccountUnlocker interface {
	AdminUnlockUser(ctx context.Context, input AdminUnlockUserInput) (*AdminUnlockUserResult, error)
}

// Service 负责用户注册以及少量管理员账号维护动作。
// 它把用户名/邮箱/密码规则、唯一性校验和密码哈希收敛在一起。
type Service struct {
	users     repository.UserRepository
	passwords securityport.PasswordVerifier
	rateLimit cacheport.RateLimitRepository
	now       func() time.Time
}

func NewService(users repository.UserRepository, passwords securityport.PasswordVerifier, rateLimit ...cacheport.RateLimitRepository) *Service {
	var repo cacheport.RateLimitRepository
	if len(rateLimit) > 0 {
		repo = rateLimit[0]
	}
	return &Service{
		users:     users,
		passwords: passwords,
		rateLimit: repo,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (s *Service) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	// 注册流程分三步：
	// 1. 校验输入格式和密码强度；
	// 2. 校验用户名/邮箱唯一性；
	// 3. 生成密码哈希并创建用户。
	username := strings.TrimSpace(input.Username)
	email := strings.ToLower(strings.TrimSpace(input.Email))
	displayName := strings.TrimSpace(input.DisplayName)

	switch {
	case !usernamePattern.MatchString(username):
		return nil, ErrInvalidUsername
	case !isValidEmail(email):
		return nil, ErrInvalidEmail
	case len(displayName) < 2 || len(displayName) > 128:
		return nil, ErrInvalidDisplayName
	case !isStrongEnoughPassword(input.Password):
		return nil, ErrWeakPassword
	}

	existingByUsername, err := s.users.FindByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if existingByUsername != nil {
		return nil, ErrUsernameAlreadyUsed
	}

	existingByEmail, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if existingByEmail != nil {
		return nil, ErrEmailAlreadyUsed
	}

	if s.passwords == nil {
		return nil, ErrWeakPassword
	}
	passwordHash, err := s.passwords.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	now := s.now()
	status := "pending_verification"
	if input.AutoActivate {
		// 某些后台场景允许直接创建 active 用户，跳过邮箱验证阶段。
		status = "active"
	}
	model := &userdomain.Model{
		UserUUID:         uuid.NewString(),
		Username:         username,
		Email:            email,
		EmailVerified:    input.EmailVerified,
		DisplayName:      displayName,
		PasswordHash:     passwordHash,
		Status:           status,
		FailedLoginCount: 0,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.users.Create(ctx, model); err != nil {
		return nil, err
	}

	return &RegisterResult{
		UserID:        model.ID,
		UserUUID:      model.UserUUID,
		Username:      model.Username,
		Email:         model.Email,
		EmailVerified: model.EmailVerified,
		DisplayName:   model.DisplayName,
		Status:        model.Status,
		CreatedAt:     now,
	}, nil
}

type passwordHashUpdater interface {
	UpdatePasswordHash(ctx context.Context, id int64, passwordHash string, updatedAt time.Time) error
}

type userAccountUnlocker interface {
	UnlockAccount(ctx context.Context, id int64, updatedAt time.Time) error
}

func (s *Service) AdminResetPassword(ctx context.Context, input AdminResetPasswordInput) (*AdminResetPasswordResult, error) {
	// 管理员重置密码不会直接改动登录状态；
	// 是否联动强制下线由更上层运维动作决定。
	if input.UserID <= 0 {
		return nil, ErrUserNotFound
	}
	if !isStrongEnoughPassword(input.NewPassword) {
		return nil, ErrWeakPassword
	}
	if s.passwords == nil {
		return nil, ErrWeakPassword
	}
	updater, ok := s.users.(passwordHashUpdater)
	if !ok {
		return nil, ErrPasswordUpdateFailed
	}

	userModel, err := s.users.FindByID(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	if userModel == nil {
		return nil, ErrUserNotFound
	}

	passwordHash, err := s.passwords.HashPassword(input.NewPassword)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if err := updater.UpdatePasswordHash(ctx, input.UserID, passwordHash, now); err != nil {
		return nil, err
	}
	return &AdminResetPasswordResult{
		UserID:        userModel.ID,
		Username:      userModel.Username,
		PasswordSetAt: now,
	}, nil
}

func (s *Service) AdminUnlockUser(ctx context.Context, input AdminUnlockUserInput) (*AdminUnlockUserResult, error) {
	// 解锁账号除了更新数据库状态，也会顺手清掉限流/锁定缓存。
	if input.UserID <= 0 {
		return nil, ErrUserNotFound
	}
	unlocker, ok := s.users.(userAccountUnlocker)
	if !ok {
		return nil, ErrUserUnlockFailed
	}
	userModel, err := s.users.FindByID(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	if userModel == nil {
		return nil, ErrUserNotFound
	}
	now := s.now()
	if err := unlocker.UnlockAccount(ctx, input.UserID, now); err != nil {
		return nil, err
	}
	if s.rateLimit != nil {
		_ = s.rateLimit.ClearUserLock(ctx, strconv.FormatInt(input.UserID, 10))
		if username := strings.TrimSpace(userModel.Username); username != "" {
			_ = s.rateLimit.ResetLoginFailByUser(ctx, username)
			_ = s.rateLimit.ResetBlacklistByUser(ctx, username)
		}
	}
	return &AdminUnlockUserResult{
		UserID:     userModel.ID,
		Username:   userModel.Username,
		UnlockedAt: now,
	}, nil
}

func isValidEmail(email string) bool {
	// 这里只做格式层面的轻量校验，不做邮箱存在性探测。
	if len(email) > 255 {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}

func isStrongEnoughPassword(password string) bool {
	// 当前密码策略比较基础：长度 + 至少一个字母和一个数字。
	password = strings.TrimSpace(password)
	if len(password) < 8 || len(password) > 128 {
		return false
	}

	var hasLetter, hasDigit bool
	for _, r := range password {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	return hasLetter && hasDigit
}
