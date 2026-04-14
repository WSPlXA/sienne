package cache

import (
	"context"
	"time"
)

// TokenCacheRepository 负责 token 的高频缓存读取、即时撤销和 refresh replay 保护。
type TokenCacheRepository interface {
	SaveAccessToken(ctx context.Context, entry AccessTokenCacheEntry, ttl time.Duration) error
	GetAccessToken(ctx context.Context, tokenSHA256 string) (*AccessTokenCacheEntry, error)

	SaveRefreshToken(ctx context.Context, entry RefreshTokenCacheEntry, ttl time.Duration) error
	GetRefreshToken(ctx context.Context, tokenSHA256 string) (*RefreshTokenCacheEntry, error)
	CheckRefreshTokenReplay(ctx context.Context, tokenSHA256 string, replayFingerprint string) (*RefreshTokenReplayResult, error)
	RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, newEntry RefreshTokenCacheEntry, response TokenResponseCacheEntry, replayFingerprint string, newTTL time.Duration, graceTTL time.Duration) error

	RevokeAccessToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error
	RevokeRefreshToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error
	IsAccessTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error)
	IsRefreshTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error)
}

// RefreshTokenReplayStatus 表示同一 refresh token 在缓存层观测到的并发/重放状态。
type RefreshTokenReplayStatus string

const (
	RefreshTokenReplayNone     RefreshTokenReplayStatus = "none"
	RefreshTokenReplayGrace    RefreshTokenReplayStatus = "grace"
	RefreshTokenReplayRejected RefreshTokenReplayStatus = "rejected"
)

type RefreshTokenReplayResult struct {
	Status   RefreshTokenReplayStatus
	Response *TokenResponseCacheEntry
}

// TokenResponseCacheEntry 用于在 refresh token grace 窗口内复用上一次成功响应。
type TokenResponseCacheEntry struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	Scope        string
	IDToken      string
}

// AccessTokenCacheEntry 是 access token 在缓存中的元数据投影。
type AccessTokenCacheEntry struct {
	TokenSHA256  string
	ClientID     string
	UserID       string
	Subject      string
	ScopesJSON   string
	AudienceJSON string
	TokenType    string
	TokenFormat  string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

// RefreshTokenCacheEntry 是 refresh token 在缓存中的生命周期记录。
type RefreshTokenCacheEntry struct {
	TokenSHA256 string
	ClientID    string
	UserID      string
	Subject     string
	ScopesJSON  string
	FamilyID    string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}
