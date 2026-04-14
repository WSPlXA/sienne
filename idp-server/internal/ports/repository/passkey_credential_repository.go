package repository

import (
	"context"
	"time"

	passkeydomain "idp-server/internal/domain/passkey"
)

// PasskeyCredentialRepository 负责用户 WebAuthn 凭据的读写与“最近使用时间”更新。
type PasskeyCredentialRepository interface {
	ListByUserID(ctx context.Context, userID int64) ([]*passkeydomain.Model, error)
	Upsert(ctx context.Context, model *passkeydomain.Model) error
	TouchByCredentialID(ctx context.Context, credentialID string, lastUsedAt time.Time) error
}
