package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

type ReplayProtectionRepository struct {
	rdb     *goredis.Client
	key     *KeyBuilder
	scripts *scriptSet
}

func NewReplayProtectionRepository(rdb *goredis.Client, key *KeyBuilder) *ReplayProtectionRepository {
	scripts, err := loadScripts()
	if err != nil {
		panic(err)
	}

	return &ReplayProtectionRepository{
		rdb:     rdb,
		key:     key,
		scripts: scripts,
	}
}

func (r *ReplayProtectionRepository) SaveState(ctx context.Context, state string, value map[string]string, ttl time.Duration) error {
	_, err := runScript(
		ctx,
		r.scripts.saveOAuthState,
		r.rdb,
		[]string{r.key.OAuthState(state)},
		value["client_id"],
		value["redirect_uri"],
		value["session_id"],
		value["created_at"],
		value["return_to"],
		value["nonce"],
		durationSeconds(ttl),
	).Result()
	return err
}

func (r *ReplayProtectionRepository) GetState(ctx context.Context, state string) (map[string]string, error) {
	result, err := r.rdb.HGetAll(ctx, r.key.OAuthState(state)).Result()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func (r *ReplayProtectionRepository) DeleteState(ctx context.Context, state string) error {
	return r.rdb.Del(ctx, r.key.OAuthState(state)).Err()
}

func (r *ReplayProtectionRepository) SaveNonce(ctx context.Context, nonce string, ttl time.Duration) error {
	result, err := runScript(
		ctx,
		r.scripts.reserveNonce,
		r.rdb,
		[]string{r.key.Nonce(nonce)},
		"1",
		durationSeconds(ttl),
	).Result()
	if err != nil {
		return err
	}
	if number, ok := result.(int64); ok && number == 1 {
		return nil
	}
	return nil
}

func (r *ReplayProtectionRepository) ExistsNonce(ctx context.Context, nonce string) (bool, error) {
	exists, err := r.rdb.Exists(ctx, r.key.Nonce(nonce)).Result()
	return exists > 0, err
}
