package redis

import (
	"context"
	"time"

	cacheport "idp-server/internal/ports/cache"

	goredis "github.com/redis/go-redis/v9"
)

type SessionCacheRepository struct {
	rdb     *goredis.Client
	key     *KeyBuilder
	scripts *scriptSet
}

func NewSessionCacheRepository(rdb *goredis.Client, key *KeyBuilder) *SessionCacheRepository {
	// session cache 用脚本同时维护两类数据：
	// 单个 session 的哈希记录，以及 user -> sessionIDs 的反向索引集合。
	scripts, err := loadScripts()
	if err != nil {
		panic(err)
	}

	return &SessionCacheRepository{
		rdb:     rdb,
		key:     key,
		scripts: scripts,
	}
}

func (r *SessionCacheRepository) Save(ctx context.Context, entry cacheport.SessionCacheEntry, ttl time.Duration) error {
	// Save 把 session 正文和用户索引一起写入 Redis，
	// 这样既能按 sessionID 取会话，也能在“全端登出”时按用户枚举会话。
	_, err := runScript(
		ctx,
		r.scripts.saveSession,
		r.rdb,
		[]string{
			r.key.Session(entry.SessionID),
			r.key.UserSessionIndex(entry.UserID),
		},
		entry.SessionID,
		entry.UserID,
		entry.Subject,
		entry.ACR,
		entry.AMRJSON,
		entry.IPAddress,
		entry.UserAgent,
		formatTime(entry.AuthenticatedAt),
		formatTime(entry.ExpiresAt),
		entry.Status,
		durationSeconds(ttl),
	).Result()
	return err
}

func (r *SessionCacheRepository) Get(ctx context.Context, sessionID string) (*cacheport.SessionCacheEntry, error) {
	// 缓存里的时间统一用 RFC3339 字符串保存，便于 Lua/Go 双端稳定读写。
	key := r.key.Session(sessionID)

	res, err := r.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, nil
	}

	authenticatedAt, _ := time.Parse(time.RFC3339, res["authenticated_at"])
	expiresAt, _ := time.Parse(time.RFC3339, res["expires_at"])

	return &cacheport.SessionCacheEntry{
		SessionID:       sessionID,
		UserID:          res["user_id"],
		Subject:         res["subject"],
		ACR:             res["acr"],
		AMRJSON:         res["amr_json"],
		IPAddress:       res["ip"],
		UserAgent:       res["user_agent"],
		AuthenticatedAt: authenticatedAt.UTC(),
		ExpiresAt:       expiresAt.UTC(),
		Status:          res["status"],
	}, nil
}

func (r *SessionCacheRepository) Delete(ctx context.Context, sessionID string) error {
	// 删除时优先读出 user_id，是为了把对应的用户索引集合也一起清掉，
	// 避免留下“索引还在但 session 实际已失效”的悬挂条目。
	entry, err := r.Get(ctx, sessionID)
	if err != nil || entry == nil {
		if err != nil {
			return err
		}
		return r.rdb.Del(ctx, r.key.Session(sessionID)).Err()
	}

	_, err = runScript(
		ctx,
		r.scripts.deleteSession,
		r.rdb,
		[]string{
			r.key.Session(sessionID),
			r.key.UserSessionIndex(entry.UserID),
		},
		sessionID,
	).Result()
	return err
}

func (r *SessionCacheRepository) AddUserSessionIndex(ctx context.Context, userID string, sessionID string, ttl time.Duration) error {
	// 单独暴露索引操作，方便少数只需要修补索引、不需要重写整个 session 的场景。
	key := r.key.UserSessionIndex(userID)

	pipe := r.rdb.TxPipeline()
	pipe.SAdd(ctx, key, sessionID)
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *SessionCacheRepository) ListUserSessionIDs(ctx context.Context, userID string) ([]string, error) {
	// 这里直接返回集合成员，由上层负责去重和进一步过滤。
	return r.rdb.SMembers(ctx, r.key.UserSessionIndex(userID)).Result()
}

func (r *SessionCacheRepository) RemoveUserSessionIndex(ctx context.Context, userID string, sessionID string) error {
	// 索引移除是幂等的，session 已不在集合中时也不会报错。
	return r.rdb.SRem(ctx, r.key.UserSessionIndex(userID), sessionID).Err()
}
