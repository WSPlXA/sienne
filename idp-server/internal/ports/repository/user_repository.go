package repository

import (
	"context"
	"time"

	"idp-server/internal/domain/user"
)

type UserRepository interface {
	Create(ctx context.Context, model *user.Model) error
	FindByID(ctx context.Context, id int64) (*user.Model, error)
	FindByUserUUID(ctx context.Context, userUUID string) (*user.Model, error)
	FindByEmail(ctx context.Context, email string) (*user.Model, error)
	FindByUsername(ctx context.Context, username string) (*user.Model, error)
	IncrementFailedLogin(ctx context.Context, id int64) (int64, error)
	ResetFailedLogin(ctx context.Context, id int64, lastLoginAt time.Time) error
}
