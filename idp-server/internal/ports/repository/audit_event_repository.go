package repository

import (
	"context"

	"idp-server/internal/domain/audit"
)

type AuditEventRepository interface {
	Create(ctx context.Context, model *audit.Model) error
}
