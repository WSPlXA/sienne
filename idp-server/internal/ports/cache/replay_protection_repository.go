package cache

import (
	"context"
	"time"
)

// ReplayProtectionRepository 抽象短时状态与 nonce 的防重放缓存。
// 目前主要服务于联邦 OIDC 登录的 state/nonce 管理。
type ReplayProtectionRepository interface {
	SaveState(ctx context.Context, state string, value map[string]string, ttl time.Duration) error
	GetState(ctx context.Context, state string) (map[string]string, error)
	DeleteState(ctx context.Context, state string) error

	SaveNonce(ctx context.Context, nonce string, ttl time.Duration) error
	ExistsNonce(ctx context.Context, nonce string) (bool, error)
}
