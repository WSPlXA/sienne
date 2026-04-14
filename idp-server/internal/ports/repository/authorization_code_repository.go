package repository

import (
	"context"
	"time"

	"idp-server/internal/domain/authorization"
)

// AuthorizationCodeRepository 抽象 authorization code 的创建与一次性消费。
// ConsumeByCode 的语义通常隐含“读并标记已消费”，以防 code 被重复兑换。
type AuthorizationCodeRepository interface {
	Create(ctx context.Context, model *authorization.Model) error
	ConsumeByCode(ctx context.Context, code string, consumedAt time.Time) (*authorization.Model, error)
}
