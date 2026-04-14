package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	cacheport "idp-server/internal/ports/cache"

	goredis "github.com/redis/go-redis/v9"
)

type TokenCacheRepository struct {
	rdb     *goredis.Client
	key     *KeyBuilder
	scripts *scriptSet
}

func NewTokenCacheRepository(rdb *goredis.Client, key *KeyBuilder) *TokenCacheRepository {
	// token cache 对 Lua 脚本有强依赖：
	// 刷新令牌轮换、撤销和 replay 检测都需要 Redis 侧原子操作。
	scripts, err := loadScripts()
	if err != nil {
		panic(err)
	}

	return &TokenCacheRepository{
		rdb:     rdb,
		key:     key,
		scripts: scripts,
	}
}

func (r *TokenCacheRepository) SaveAccessToken(ctx context.Context, entry cacheport.AccessTokenCacheEntry, ttl time.Duration) error {
	// access token 在缓存里保存的是“可快速校验/内省的元数据快照”，
	// 键使用 token 的 SHA256，而不是明文 token，降低泄露风险。
	data := map[string]any{
		"client_id":    entry.ClientID,
		"user_id":      entry.UserID,
		"subject":      entry.Subject,
		"scopes_json":  entry.ScopesJSON,
		"aud_json":     entry.AudienceJSON,
		"token_type":   entry.TokenType,
		"token_format": entry.TokenFormat,
		"issued_at":    formatTime(entry.IssuedAt),
		"expires_at":   formatTime(entry.ExpiresAt),
		"revoked":      "0",
	}
	pipe := r.rdb.TxPipeline()
	pipe.HSet(ctx, r.key.AccessToken(entry.TokenSHA256), data)
	pipe.Expire(ctx, r.key.AccessToken(entry.TokenSHA256), ttl)
	// HSET + EXPIRE 放进同一个 pipeline，减少往返并避免留下无 TTL 的脏 key。
	_, err := pipe.Exec(ctx)
	return err
}

func (r *TokenCacheRepository) GetAccessToken(ctx context.Context, tokenSHA256 string) (*cacheport.AccessTokenCacheEntry, error) {
	// 不存在时返回 nil, nil，方便上层把“缓存未命中”与“缓存出错”分开处理。
	result, err := r.rdb.HGetAll(ctx, r.key.AccessToken(tokenSHA256)).Result()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	return &cacheport.AccessTokenCacheEntry{
		TokenSHA256:  tokenSHA256,
		ClientID:     result["client_id"],
		UserID:       result["user_id"],
		Subject:      result["subject"],
		ScopesJSON:   result["scopes_json"],
		AudienceJSON: result["aud_json"],
		TokenType:    result["token_type"],
		TokenFormat:  result["token_format"],
		IssuedAt:     parseTime(result["issued_at"]),
		ExpiresAt:    parseTime(result["expires_at"]),
	}, nil
}

func (r *TokenCacheRepository) SaveRefreshToken(ctx context.Context, entry cacheport.RefreshTokenCacheEntry, ttl time.Duration) error {
	// family_id 用来把一串轮换出来的 refresh token 视为同一个“家族”，
	// 一旦发现 replay，可以按家族维度做更强的处置。
	familyID := entry.FamilyID
	if familyID == "" {
		familyID = entry.TokenSHA256
	}
	data := map[string]any{
		"client_id":   entry.ClientID,
		"user_id":     entry.UserID,
		"subject":     entry.Subject,
		"scopes_json": entry.ScopesJSON,
		"issued_at":   formatTime(entry.IssuedAt),
		"expires_at":  formatTime(entry.ExpiresAt),
		"status":      "active",
		"revoked":     "0",
		"family_id":   familyID,
		"rotated_to":  "",
	}
	pipe := r.rdb.TxPipeline()
	pipe.HSet(ctx, r.key.RefreshToken(entry.TokenSHA256), data)
	pipe.Expire(ctx, r.key.RefreshToken(entry.TokenSHA256), ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *TokenCacheRepository) GetRefreshToken(ctx context.Context, tokenSHA256 string) (*cacheport.RefreshTokenCacheEntry, error) {
	// refresh token 读取主要服务于轮换/回放保护，不需要回传完整明文 token。
	result, err := r.rdb.HGetAll(ctx, r.key.RefreshToken(tokenSHA256)).Result()
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, nil
	}
	return &cacheport.RefreshTokenCacheEntry{
		TokenSHA256: tokenSHA256,
		ClientID:    result["client_id"],
		UserID:      result["user_id"],
		Subject:     result["subject"],
		ScopesJSON:  result["scopes_json"],
		IssuedAt:    parseTime(result["issued_at"]),
		ExpiresAt:   parseTime(result["expires_at"]),
	}, nil
}

func (r *TokenCacheRepository) RevokeAccessToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error {
	// 撤销操作通过 Lua 一次性完成：
	// 更新原 token 记录并写入 revoked 标记键，后续中间件只查后者即可快速拦截。
	_, err := runScript(
		ctx,
		r.scripts.revokeToken,
		r.rdb,
		[]string{
			r.key.AccessToken(tokenSHA256),
			r.key.RevokedAccessToken(tokenSHA256),
			"",
		},
		durationSeconds(ttl),
	).Result()
	return err
}

func (r *TokenCacheRepository) RevokeRefreshToken(ctx context.Context, tokenSHA256 string, ttl time.Duration) error {
	// refresh token 的撤销逻辑和 access token 类似，但命中的是另一组 key 空间。
	_, err := runScript(
		ctx,
		r.scripts.revokeToken,
		r.rdb,
		[]string{
			r.key.RefreshToken(tokenSHA256),
			r.key.RevokedRefreshToken(tokenSHA256),
			"",
		},
		durationSeconds(ttl),
	).Result()
	return err
}

func (r *TokenCacheRepository) IsAccessTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error) {
	// 撤销判断只看哨兵键是否存在，尽量把高频校验路径压到 O(1)。
	exists, err := r.rdb.Exists(ctx, r.key.RevokedAccessToken(tokenSHA256)).Result()
	return exists > 0, err
}

func (r *TokenCacheRepository) IsRefreshTokenRevoked(ctx context.Context, tokenSHA256 string) (bool, error) {
	exists, err := r.rdb.Exists(ctx, r.key.RevokedRefreshToken(tokenSHA256)).Result()
	return exists > 0, err
}

func (r *TokenCacheRepository) CheckRefreshTokenReplay(ctx context.Context, tokenSHA256 string, replayFingerprint string) (*cacheport.RefreshTokenReplayResult, error) {
	// replay 检测分三种结果：
	// 1. none: 没有竞争，允许继续轮换；
	// 2. grace: 这是同一请求窗口内的重试，可以复用上次成功响应；
	// 3. rejected: 明确判定为重放或家族已失效。
	cmd := runScript(
		ctx,
		r.scripts.checkRefreshReplay,
		r.rdb,
		[]string{
			r.key.RefreshToken(tokenSHA256),
			r.key.RefreshTokenGrace(tokenSHA256),
			r.key.RefreshTokenFamilyRevoked(""),
		},
		time.Now().UTC().Unix(),
		replayFingerprint,
		tokenSHA256,
	)
	values, err := cmd.Result()
	if err != nil {
		return nil, err
	}
	parts, ok := values.([]any)
	if !ok || len(parts) < 2 {
		return nil, fmt.Errorf("unexpected refresh replay script result: %T", values)
	}

	code, err := luaInt64(parts[0])
	if err != nil {
		return nil, err
	}
	payload, err := luaString(parts[1])
	if err != nil {
		return nil, err
	}

	switch code {
	case 0:
		return &cacheport.RefreshTokenReplayResult{Status: cacheport.RefreshTokenReplayNone}, nil
	case 1:
		// grace 返回里会带上上一次成功轮换时缓存的 token 响应，
		// 这样并发重试请求能拿到一致结果，而不是随机失败。
		response := &cacheport.TokenResponseCacheEntry{}
		if err := json.Unmarshal([]byte(payload), response); err != nil {
			return nil, err
		}
		return &cacheport.RefreshTokenReplayResult{
			Status:   cacheport.RefreshTokenReplayGrace,
			Response: response,
		}, nil
	case -1:
		return &cacheport.RefreshTokenReplayResult{Status: cacheport.RefreshTokenReplayRejected}, nil
	default:
		return nil, fmt.Errorf("unexpected refresh replay script code: %d", code)
	}
}

func (r *TokenCacheRepository) RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, newEntry cacheport.RefreshTokenCacheEntry, response cacheport.TokenResponseCacheEntry, replayFingerprint string, newTTL time.Duration, graceTTL time.Duration) error {
	// 刷新令牌轮换必须是原子的：
	// 标记旧 token 已轮换、写入新 token、记录 grace 响应，任一步拆开都会产生竞态。
	responseJSON, err := json.Marshal(response)
	if err != nil {
		return err
	}
	if newEntry.FamilyID == "" {
		newEntry.FamilyID = oldTokenSHA256
	}
	result, err := runScript(
		ctx,
		r.scripts.rotateToken,
		r.rdb,
		[]string{
			r.key.RefreshToken(oldTokenSHA256),
			r.key.RefreshToken(newEntry.TokenSHA256),
			r.key.RefreshTokenGrace(oldTokenSHA256),
			r.key.RefreshTokenFamilyRevoked(""),
			"",
			"",
		},
		oldTokenSHA256,
		newEntry.TokenSHA256,
		newEntry.ClientID,
		newEntry.UserID,
		newEntry.Subject,
		newEntry.ScopesJSON,
		formatTime(newEntry.IssuedAt),
		formatTime(newEntry.ExpiresAt),
		durationSeconds(newTTL),
		durationSeconds(graceTTL),
		time.Now().UTC().Unix(),
		replayFingerprint,
		string(responseJSON),
	).Int64()
	if err != nil {
		return err
	}
	switch result {
	case 1:
		return nil
	case -1:
		return errors.New("refresh token not found in cache")
	case -2:
		return errors.New("refresh token already rotated in cache")
	case -3:
		return errors.New("refresh token family revoked in cache")
	default:
		return fmt.Errorf("unexpected refresh token rotate result: %d", result)
	}
}

func luaInt64(value any) (int64, error) {
	// go-redis 对 Lua 返回值的解码类型不固定，这里集中做一层兼容。
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case string:
		return strconv.ParseInt(typed, 10, 64)
	case []byte:
		return strconv.ParseInt(string(typed), 10, 64)
	default:
		return 0, fmt.Errorf("unexpected lua integer type: %T", value)
	}
}

func luaString(value any) (string, error) {
	// 同上，把脚本返回的 string / []byte / nil 统一整理成 Go string。
	switch typed := value.(type) {
	case string:
		return typed, nil
	case []byte:
		return string(typed), nil
	case nil:
		return "", nil
	default:
		return "", fmt.Errorf("unexpected lua string type: %T", value)
	}
}
