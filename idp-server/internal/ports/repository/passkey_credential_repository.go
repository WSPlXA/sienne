package repository

import (
	"context"
	"time"

	passkeydomain "idp-server/internal/domain/passkey"
)

type PasskeyCredentialRepository interface {
	ListByUserID(ctx context.Context, userID int64) ([]*passkeydomain.Model, error)
	Upsert(ctx context.Context, model *passkeydomain.Model) error
	TouchByCredentialID(ctx context.Context, credentialID string, lastUsedAt time.Time) error
}
