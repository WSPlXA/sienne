package repository

import (
	"context"

	totpdomain "idp-server/internal/domain/totp"
)

// TOTPRepository 抽象用户 TOTP 凭据的持久化操作。
type TOTPRepository interface {
	FindByUserID(ctx context.Context, userID int64) (*totpdomain.Model, error)
	Upsert(ctx context.Context, model *totpdomain.Model) error
	DeleteByUserID(ctx context.Context, userID int64) error
}
