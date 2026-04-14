package repository

import (
	"context"
	"time"

	"idp-server/internal/domain/audit"
)

// ListAuditEventsInput 描述审计列表查询时允许的筛选条件。
type ListAuditEventsInput struct {
	Limit     int
	Offset    int
	EventType string
	UserID    *int64
	Subject   string
	From      *time.Time
	To        *time.Time
}

// AuditEventRepository 定义审计事件的写入与分页查询接口。
type AuditEventRepository interface {
	Create(ctx context.Context, model *audit.Model) error
	List(ctx context.Context, input ListAuditEventsInput) ([]*audit.Model, error)
}
