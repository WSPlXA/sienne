package cache

import (
	"context"
	"time"
)

// MFARepository 缓存所有短生命周期的 MFA 状态：
// TOTP enrollment、登录 challenge、Passkey session 以及 TOTP step 重放保护。
type MFARepository interface {
	SaveTOTPEnrollment(ctx context.Context, entry TOTPEnrollmentEntry, ttl time.Duration) error
	GetTOTPEnrollment(ctx context.Context, sessionID string) (*TOTPEnrollmentEntry, error)
	DeleteTOTPEnrollment(ctx context.Context, sessionID string) error
	ReserveTOTPStepUse(ctx context.Context, userID, purpose string, step int64, ttl time.Duration) (bool, error)

	SaveMFAChallenge(ctx context.Context, entry MFAChallengeEntry, ttl time.Duration) error
	GetMFAChallenge(ctx context.Context, challengeID string) (*MFAChallengeEntry, error)
	DeleteMFAChallenge(ctx context.Context, challengeID string) error
}

const (
	// 不同 purpose 让同一用户在不同业务场景下的 TOTP step 重放保护相互隔离。
	TOTPPurposeLogin         = "login"
	TOTPPurposeEnable2FA     = "enable_2fa"
	TOTPPurposeResetPassword = "reset_password"
)

// TOTPEnrollmentEntry 表示“已生成 secret，但尚未通过验证码确认启用”的临时绑定记录。
type TOTPEnrollmentEntry struct {
	SessionID       string
	UserID          string
	Secret          string
	ProvisioningURI string
	ExpiresAt       time.Time
}

// MFAChallengeEntry 是登录第二阶段使用的挑战上下文。
// 不同 MFA 方式会复用这个结构的不同字段。
type MFAChallengeEntry struct {
	ChallengeID        string
	UserID             string
	Subject            string
	Username           string
	IPAddress          string
	UserAgent          string
	ReturnTo           string
	RedirectURI        string
	MFAMode            string
	PushStatus         string
	PushCode           string
	ApproverUserID     string
	DecidedAt          time.Time
	PasskeySessionJSON string
	ExpiresAt          time.Time
	StateMask          uint32
	StateVersion       uint32
}
