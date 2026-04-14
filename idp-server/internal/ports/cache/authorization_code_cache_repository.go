package cache

import (
	"context"
	"time"
)

// AuthorizationCodeCacheRepository 预留给 authorization code 的缓存层优化。
// 当前主流程更多依赖数据库一次性消费，但这里保留了短时缓存接口以备扩展。
type AuthorizationCodeCacheRepository interface {
	Save(ctx context.Context, key AuthorizationCodeCacheEntry, ttl time.Duration) error
	Get(ctx context.Context, code string) (*AuthorizationCodeCacheEntry, error)
	Delete(ctx context.Context, code string) error
	IsConsumed(ctx context.Context, code string) (bool, error)
	MarkAsConsumed(ctx context.Context, code string) error
}

// AuthorizationCodeCacheEntry 是授权码在缓存中的最小状态投影。
type AuthorizationCodeCacheEntry struct {
	Code      string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt time.Time
	Consumed  bool
}
