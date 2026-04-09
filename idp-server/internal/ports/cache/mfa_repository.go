package cache

import (
	"context"
	"time"
)

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
	TOTPPurposeLogin         = "login"
	TOTPPurposeEnable2FA     = "enable_2fa"
	TOTPPurposeResetPassword = "reset_password"
)

type TOTPEnrollmentEntry struct {
	SessionID       string
	UserID          string
	Secret          string
	ProvisioningURI string
	ExpiresAt       time.Time
}

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
}
