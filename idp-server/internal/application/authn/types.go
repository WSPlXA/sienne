package authn

import (
	"errors"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserLocked         = errors.New("user is locked")
	ErrUserDisabled       = errors.New("user is disabled")
	ErrRateLimited        = errors.New("rate limit exceeded")
	ErrUnsupportedMethod  = errors.New("unsupported authentication method")
)

type RateLimitPolicy struct {
	FailureWindow     time.Duration
	MaxFailuresPerIP  int64
	MaxFailuresPerUser int64
	UserLockThreshold int64
	UserLockTTL       time.Duration
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
	SessionID       string
	UserID          int64
	Subject         string
	RedirectURI     string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}
