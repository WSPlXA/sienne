package passkey

import (
	"errors"
	"time"
)

var (
	ErrLoginRequired         = errors.New("login required")
	ErrPasskeyDisabled       = errors.New("passkey is not enabled")
	ErrPasskeySetupExpired   = errors.New("passkey setup expired")
	ErrPasskeyCredentialSave = errors.New("failed to save passkey credential")
)

type BeginSetupResult struct {
	SetupID     string
	OptionsJSON []byte
	ExpiresAt   time.Time
}

type FinishSetupResult struct {
	CredentialID string
}
