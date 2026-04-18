package mfa

import (
	"context"
	"errors"
)

var (
	ErrLoginRequired     = errors.New("login required")
	ErrAlreadyEnabled    = errors.New("totp already enabled")
	ErrEnrollmentExpired = errors.New("totp enrollment expired")
	ErrInvalidTOTPCode   = errors.New("invalid totp code")
	ErrTOTPCodeReused    = errors.New("totp code already used")
)

type Manager interface {
	BeginSetup(ctx context.Context, sessionID string) (*SetupResult, error)
	ConfirmSetup(ctx context.Context, sessionID string, code string, returnTo string) (*ConfirmResult, error)
	BeginLoginChallenge(ctx context.Context, sessionID string, returnTo string) (*ConfirmResult, error)
}

type SetupResult struct {
	Secret          string
	ProvisioningURI string
	AlreadyEnabled  bool
}

type ConfirmResult struct {
	Enabled        bool
	TOTPRequired   bool
	MFAChallengeID string
	RedirectURI    string
	ReturnTo       string
}
