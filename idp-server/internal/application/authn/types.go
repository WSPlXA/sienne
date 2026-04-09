package authn

import (
	"errors"
	"time"
)

var (
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUserLocked            = errors.New("user is locked")
	ErrUserDisabled          = errors.New("user is disabled")
	ErrRateLimited           = errors.New("rate limit exceeded")
	ErrUnsupportedMethod     = errors.New("unsupported authentication method")
	ErrMFARequired           = errors.New("mfa required")
	ErrMFAEnrollmentRequired = errors.New("mfa enrollment required")
	ErrInvalidTOTPCode       = errors.New("invalid totp code")
	ErrTOTPCodeReused        = errors.New("totp code already used")
	ErrMFAChallengeExpired   = errors.New("mfa challenge expired")
	ErrMFAPushNotApproved    = errors.New("mfa push not approved")
	ErrMFAPushRejected       = errors.New("mfa push rejected")
	ErrInvalidMFAAction      = errors.New("invalid mfa action")
	ErrMFAApproverMismatch   = errors.New("mfa approver mismatch")
	ErrInvalidPushMatchCode  = errors.New("invalid push match code")
)

type RateLimitPolicy struct {
	FailureWindow      time.Duration
	MaxFailuresPerIP   int64
	MaxFailuresPerUser int64
	UserLockThreshold  int64
	UserLockTTL        time.Duration
}

func DefaultRateLimitPolicy() RateLimitPolicy {
	return RateLimitPolicy{
		FailureWindow:      15 * time.Minute,
		MaxFailuresPerIP:   20,
		MaxFailuresPerUser: 5,
		UserLockThreshold:  5,
		UserLockTTL:        30 * time.Minute,
	}
}

type AuthenticateInput struct {
	Method      string
	Username    string
	Password    string
	RedirectURI string
	ReturnTo    string
	State       string
	Code        string
	Nonce       string
	IPAddress   string
	UserAgent   string
}

type AuthenticateResult struct {
	SessionID             string
	UserID                int64
	Subject               string
	RedirectURI           string
	ReturnTo              string
	MFARequired           bool
	MFAEnrollmentRequired bool
	MFAChallengeID        string
	MFAMode               string
	PushStatus            string
	PushCode              string
	AuthenticatedAt       time.Time
	ExpiresAt             time.Time
}

type VerifyTOTPInput struct {
	ChallengeID string
	Code        string
	IPAddress   string
	UserAgent   string
}

type PollMFAChallengeInput struct {
	ChallengeID string
}

type PollMFAChallengeResult struct {
	ChallengeID string
	MFAMode     string
	PushStatus  string
	PushCode    string
	ExpiresAt   time.Time
}

type DecideMFAPushInput struct {
	ChallengeID       string
	ApproverSessionID string
	Action            string
	MatchCode         string
	IPAddress         string
	UserAgent         string
}

type FinalizeMFAPushInput struct {
	ChallengeID string
}

const (
	MFAModeTOTPOnly         = "totp_only"
	MFAModePushTOTPFallback = "push_totp_fallback"
	MFAPushStatusPending    = "pending"
	MFAPushStatusApproved   = "approved"
	MFAPushStatusDenied     = "denied"
)
