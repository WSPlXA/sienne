package passkey

import "time"

type Model struct {
	ID             int64
	UserID         int64
	CredentialID   string
	CredentialJSON string
	LastUsedAt     *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
