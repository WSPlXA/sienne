package repository

import (
	"context"

	operatorroledomain "idp-server/internal/domain/operatorrole"
)

type OperatorRoleRepository interface {
	Upsert(ctx context.Context, model *operatorroledomain.Model) error
	Create(ctx context.Context, model *operatorroledomain.Model) error
	Update(ctx context.Context, model *operatorroledomain.Model) error
	DeleteByRoleCode(ctx context.Context, roleCode string) error
	FindByRoleCode(ctx context.Context, roleCode string) (*operatorroledomain.Model, error)
	List(ctx context.Context) ([]*operatorroledomain.Model, error)
}
