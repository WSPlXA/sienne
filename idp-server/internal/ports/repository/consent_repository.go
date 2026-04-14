package repository

import (
	"context"
	"time"
)

// ConsentRepository 负责记录“某个用户是否已经对某客户端/某组 scope 授权过”。
type ConsentRepository interface {
	HasActiveConsent(ctx context.Context, userID, clientID int64, scopes []string) (bool, error)
	UpsertActiveConsent(ctx context.Context, userID, clientID int64, scopes []string, grantedAt time.Time) error
}
