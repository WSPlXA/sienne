package cache

import (
	"context"
	"time"
)

// SessionCacheRepository 定义会话缓存层接口。
// 它既缓存单个 session，也维护 user -> sessionIDs 的索引，便于批量下线。
type SessionCacheRepository interface {
	Save(ctx context.Context, key SessionCacheEntry, ttl time.Duration) error
	Get(ctx context.Context, sessionID string) (*SessionCacheEntry, error)
	Delete(ctx context.Context, sessionID string) error

	AddUserSessionIndex(ctx context.Context, userID string, sessionID string, ttl time.Duration) error
	ListUserSessionIDs(ctx context.Context, userID string) ([]string, error)
	RemoveUserSessionIndex(ctx context.Context, userID string, sessionID string) error
}

// SessionCacheEntry 是写入 Redis 的会话快照。
type SessionCacheEntry struct {
	SessionID       string
	UserID          string
	Subject         string
	ACR             string
	AMRJSON         string
	IPAddress       string
	UserAgent       string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	Status          string
	StateMask       uint32
	StateVersion    uint32
}
