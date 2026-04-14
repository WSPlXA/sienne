package cache

import (
	"context"
	"time"
)

// DeviceCodeRepository 定义 OAuth2 Device Authorization Grant 在缓存层需要的状态操作。
type DeviceCodeRepository interface {
	Save(ctx context.Context, entry DeviceCodeEntry, ttl time.Duration) error
	GetByDeviceCode(ctx context.Context, deviceCode string) (*DeviceCodeEntry, error)
	GetByUserCode(ctx context.Context, userCode string) (*DeviceCodeEntry, error)
	Approve(ctx context.Context, userCode string, userID string, subject string, approvedAt time.Time) error
	Deny(ctx context.Context, userCode string, deniedAt time.Time) error
	MarkConsumed(ctx context.Context, deviceCode string, consumedAt time.Time) error
	TouchPoll(ctx context.Context, deviceCode string, polledAt time.Time, minInterval time.Duration) (bool, error)
}

// DeviceCodeEntry 表示一条设备授权流程的缓存记录。
// 它会在 pending -> approved/denied -> consumed 之间迁移状态。
type DeviceCodeEntry struct {
	DeviceCode   string
	UserCode     string
	ClientID     string
	ClientName   string
	ScopesJSON   string
	Status       string
	UserID       string
	Subject      string
	ExpiresAt    time.Time
	ApprovedAt   time.Time
	DeniedAt     time.Time
	ConsumedAt   time.Time
	LastPolledAt time.Time
	Interval     int64
}
