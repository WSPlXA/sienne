package cache

import (
	"context"
	"time"
)

type RateLimitRepository interface {
	IncrementLoginFailByUser(ctx context.Context, username string, ttl time.Duration) (int64, error)
	IncrementLoginFailByIP(ctx context.Context, ip string, ttl time.Duration) (int64, error)

	GetLoginFailByUser(ctx context.Context, username string) (int64, error)
	GetLoginFailByIP(ctx context.Context, ip string) (int64, error)
	ResetLoginFailByUser(ctx context.Context, username string) error
	ResetLoginFailByIP(ctx context.Context, ip string) error

	SetUserLock(ctx context.Context, userID string, ttl time.Duration) error
	IsUserLocked(ctx context.Context, userID string) (bool, error)
}
