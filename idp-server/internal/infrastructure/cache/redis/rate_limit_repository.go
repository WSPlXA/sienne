package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

type RateLimitRepository struct {
	rdb     *goredis.Client
	key     *KeyBuilder
	scripts *scriptSet
}

func NewRateLimitRepository(rdb *goredis.Client, key *KeyBuilder) *RateLimitRepository {
	scripts, err := loadScripts()
	if err != nil {
		panic(err)
	}

	return &RateLimitRepository{
		rdb:     rdb,
		key:     key,
		scripts: scripts,
	}
}

func (r *RateLimitRepository) IncrementLoginFailByUser(ctx context.Context, username string, ttl time.Duration) (int64, error) {
	key := r.key.LoginFailUser(username)

	result, err := runScript(
		ctx,
		r.scripts.incrementWithTTL,
		r.rdb,
		[]string{key, ""},
		durationSeconds(ttl),
		0,
		0,
	).Result()
	if err != nil {
		return 0, err
	}
	values, ok := result.([]any)
	if !ok || len(values) == 0 {
		return 0, nil
	}
	return values[0].(int64), nil
}

func (r *RateLimitRepository) IncrementLoginFailByIP(ctx context.Context, ip string, ttl time.Duration) (int64, error) {
	result, err := runScript(
		ctx,
		r.scripts.incrementWithTTL,
		r.rdb,
		[]string{r.key.LoginFailIP(ip), ""},
		durationSeconds(ttl),
		0,
		0,
	).Result()
	if err != nil {
		return 0, err
	}
	values, ok := result.([]any)
	if !ok || len(values) == 0 {
		return 0, nil
	}
	return values[0].(int64), nil
}

func (r *RateLimitRepository) GetLoginFailByUser(ctx context.Context, username string) (int64, error) {
	value, err := r.rdb.Get(ctx, r.key.LoginFailUser(username)).Result()
	if err == goredis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return parseInt64(value), nil
}

func (r *RateLimitRepository) GetLoginFailByIP(ctx context.Context, ip string) (int64, error) {
	value, err := r.rdb.Get(ctx, r.key.LoginFailIP(ip)).Result()
	if err == goredis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return parseInt64(value), nil
}

func (r *RateLimitRepository) ResetLoginFailByUser(ctx context.Context, username string) error {
	return r.rdb.Del(ctx, r.key.LoginFailUser(username)).Err()
}

func (r *RateLimitRepository) ResetLoginFailByIP(ctx context.Context, ip string) error {
	return r.rdb.Del(ctx, r.key.LoginFailIP(ip)).Err()
}

func (r *RateLimitRepository) SetUserLock(ctx context.Context, userID string, ttl time.Duration) error {
	return r.rdb.Set(ctx, r.key.UserLock(userID), "1", ttl).Err()
}

func (r *RateLimitRepository) IsUserLocked(ctx context.Context, userID string) (bool, error) {
	exists, err := r.rdb.Exists(ctx, r.key.UserLock(userID)).Result()
	return exists > 0, err
}
