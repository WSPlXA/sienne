package repository

import (
	"context"
	"time"

	"idp-server/internal/domain/user"
)

// UserRepository 定义用户实体在持久化层的核心读写能力。
// 这个接口同时服务登录、后台管理和 RBAC 分配，因此既有查找也有状态更新方法。
type UserRepository interface {
	Create(ctx context.Context, model *user.Model) error
	FindByID(ctx context.Context, id int64) (*user.Model, error)
	FindByUserUUID(ctx context.Context, userUUID string) (*user.Model, error)
	FindByEmail(ctx context.Context, email string) (*user.Model, error)
	FindByUsername(ctx context.Context, username string) (*user.Model, error)
	ListByRoleCode(ctx context.Context, roleCode string, limit int) ([]*user.Model, error)
	CountByRoleCode(ctx context.Context, roleCode string) (int64, error)
	UpdateRoleAndPrivilege(ctx context.Context, id int64, roleCode string, privilegeMask uint32, tenantScope string) error
	UnlockAccount(ctx context.Context, id int64, updatedAt time.Time) error
	IncrementFailedLogin(ctx context.Context, id int64) (int64, error)
	ResetFailedLogin(ctx context.Context, id int64, lastLoginAt time.Time) error
}
