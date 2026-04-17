package redis

import (
	"context"
	"strconv"
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
	stateMask := cacheport.NormalizeSessionStateMask(entry.StateMask, entry.Status)
	stateVersion := entry.StateVersion
	if stateVersion == 0 {
		stateVersion = 1
	}
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
		cacheport.SessionStatusFromMask(stateMask, entry.Status),
		durationSeconds(ttl),
		strconv.FormatUint(uint64(stateMask), 10),
		strconv.FormatUint(uint64(stateVersion), 10),
	).Result()
	return err
}

func (r *SessionCacheRepository) Get(ctx context.Context, sessionID string) (*cacheport.SessionCacheEntry, error) {
	// 热路径改为固定字段 HMGET，避免 HGETALL map 分配和哈希遍历。
	key := r.key.Session(sessionID)
	values, err := r.rdb.HMGet(
		ctx,
		key,
		"user_id",
		"subject",
		"acr",
		"amr_json",
		"ip",
		"user_agent",
		"authenticated_at",
		"expires_at",
		"status",
		"state_mask",
		"state_ver",
	).Result()
	if err != nil {
		return nil, err
	}
	if len(values) == 0 || values[0] == nil {
		return nil, nil
	}

	authenticatedAt := parseTime(readRedisString(values[6]))
	expiresAt := parseTime(readRedisString(values[7]))
	stateMask := cacheport.NormalizeSessionStateMask(parseUint32(readRedisString(values[9])), readRedisString(values[8]))
	status := cacheport.SessionStatusFromMask(stateMask, readRedisString(values[8]))

	return &cacheport.SessionCacheEntry{
		SessionID:       sessionID,
		UserID:          readRedisString(values[0]),
		Subject:         readRedisString(values[1]),
		ACR:             readRedisString(values[2]),
		AMRJSON:         readRedisString(values[3]),
		IPAddress:       readRedisString(values[4]),
		UserAgent:       readRedisString(values[5]),
		AuthenticatedAt: authenticatedAt.UTC(),
		ExpiresAt:       expiresAt.UTC(),
		Status:          status,
		StateMask:       stateMask,
		StateVersion:    parseUint32(readRedisString(values[10])),
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

func readRedisString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}
