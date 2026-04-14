package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	tokendomain "idp-server/internal/domain/token"
)

type TokenRepository struct {
	db *sql.DB
}

func NewTokenRepository(db *sql.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) CreateAccessToken(ctx context.Context, model *tokendomain.AccessToken) error {
	// access token 明文会写库，便于某些审计或兼容场景使用；
	// 但后续查找主要仍走 SHA256，减少直接以明文做索引的需求。
	result, err := r.db.ExecContext(
		ctx,
		tokenRepositorySQL.createAccessToken,
		model.TokenValue,
		model.TokenSHA256,
		model.ClientID,
		nullInt64(model.UserID),
		model.Subject,
		nullString(model.AudienceJSON),
		model.ScopesJSON,
		model.TokenType,
		model.TokenFormat,
		model.IssuedAt,
		model.ExpiresAt,
		nullTime(model.RevokedAt),
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err == nil {
		model.ID = id
	}
	return nil
}

func (r *TokenRepository) CreateRefreshToken(ctx context.Context, model *tokendomain.RefreshToken) error {
	// refresh token 也单独持久化，为撤销、轮换和用户级别强制下线提供数据库真相来源。
	result, err := r.db.ExecContext(
		ctx,
		tokenRepositorySQL.createRefreshToken,
		model.TokenValue,
		model.TokenSHA256,
		model.ClientID,
		nullInt64(model.UserID),
		model.Subject,
		model.ScopesJSON,
		model.IssuedAt,
		model.ExpiresAt,
		nullTime(model.RevokedAt),
		nullInt64(model.ReplacedByTokenID),
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err == nil {
		model.ID = id
	}
	return nil
}

func (r *TokenRepository) FindActiveAccessTokenBySHA256(ctx context.Context, tokenSHA256 string) (*tokendomain.AccessToken, error) {
	// “active” 的语义由 SQL 保证：未撤销且未过期。
	row := r.db.QueryRowContext(ctx, tokenRepositorySQL.findActiveAccessBySHA256, tokenSHA256)
	model, err := scanAccessToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return model, nil
}

func (r *TokenRepository) FindActiveRefreshTokenBySHA256(ctx context.Context, tokenSHA256 string) (*tokendomain.RefreshToken, error) {
	// 对 refresh token 的读取也同样只看活动记录，避免上层重复判断撤销状态。
	row := r.db.QueryRowContext(ctx, tokenRepositorySQL.findActiveRefreshBySHA256, tokenSHA256)
	model, err := scanRefreshToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return model, nil
}

func (r *TokenRepository) ListActiveAccessTokensByUserID(ctx context.Context, userID int64) ([]*tokendomain.AccessToken, error) {
	// 这个列表主要用于“注销全部会话 / 管理员强制下线”时批量撤销用户 token。
	rows, err := r.db.QueryContext(ctx, tokenRepositorySQL.listActiveAccessByUserID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*tokendomain.AccessToken
	for rows.Next() {
		model, err := scanAccessToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, model)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

func (r *TokenRepository) ListActiveRefreshTokensByUserID(ctx context.Context, userID int64) ([]*tokendomain.RefreshToken, error) {
	// access 和 refresh 分开列出，是因为缓存黑名单和后续处理策略并不完全相同。
	rows, err := r.db.QueryContext(ctx, tokenRepositorySQL.listActiveRefreshByUserID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*tokendomain.RefreshToken
	for rows.Next() {
		model, err := scanRefreshToken(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, model)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return tokens, nil
}

func (r *TokenRepository) RevokeAccessTokensByUserID(ctx context.Context, userID int64, revokedAt time.Time) error {
	// 这里是批量打标，不逐条删除，便于保留审计轨迹。
	_, err := r.db.ExecContext(ctx, tokenRepositorySQL.revokeAccessByUserID, revokedAt, userID)
	return err
}

func (r *TokenRepository) RevokeRefreshTokensByUserID(ctx context.Context, userID int64, revokedAt time.Time) error {
	// refresh token 撤销后，上层通常还会同步写 Redis 黑名单以实现即时生效。
	_, err := r.db.ExecContext(ctx, tokenRepositorySQL.revokeRefreshByUserID, revokedAt, userID)
	return err
}

func (r *TokenRepository) RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, revokedAt time.Time, newToken *tokendomain.RefreshToken) error {
	// DB 层的 refresh token 轮换通过事务完成：
	// 锁旧 token -> 校验仍可用 -> 插入新 token -> 回写旧 token 的 replaced_by。
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	oldToken, err := scanRefreshToken(tx.QueryRowContext(ctx, tokenRepositorySQL.rotateFindOldForUpdate, oldTokenSHA256))
	if err != nil {
		return err
	}
	// 只要旧 token 已撤销、已被替换或已过期，就按“找不到可用记录”处理，
	// 让上层统一进入 replay / invalid token 分支。
	if oldToken == nil || oldToken.RevokedAt != nil || oldToken.ReplacedByTokenID != nil || !oldToken.ExpiresAt.After(revokedAt) {
		return sql.ErrNoRows
	}

	result, err := tx.ExecContext(
		ctx,
		tokenRepositorySQL.rotateInsertNewRefresh,
		newToken.TokenValue,
		newToken.TokenSHA256,
		newToken.ClientID,
		nullInt64(newToken.UserID),
		newToken.Subject,
		newToken.ScopesJSON,
		newToken.IssuedAt,
		newToken.ExpiresAt,
		nullTime(newToken.RevokedAt),
		nullInt64(newToken.ReplacedByTokenID),
	)
	if err != nil {
		return err
	}
	insertedID, err := result.LastInsertId()
	if err == nil {
		newToken.ID = insertedID
	}

	if _, err := tx.ExecContext(ctx, tokenRepositorySQL.rotateUpdateOldRefresh, revokedAt, newToken.ID, oldToken.ID); err != nil {
		return err
	}

	return tx.Commit()
}

func scanRefreshToken(row scanner) (*tokendomain.RefreshToken, error) {
	// scan 方法集中处理 nullable 列到指针字段的映射，避免仓储方法里重复样板代码。
	var model tokendomain.RefreshToken
	var userID sql.NullInt64
	var revokedAt sql.NullTime
	var replacedBy sql.NullInt64
	err := row.Scan(
		&model.ID,
		&model.TokenValue,
		&model.TokenSHA256,
		&model.ClientID,
		&userID,
		&model.Subject,
		&model.ScopesJSON,
		&model.IssuedAt,
		&model.ExpiresAt,
		&revokedAt,
		&replacedBy,
		&model.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if userID.Valid {
		value := userID.Int64
		model.UserID = &value
	}
	if revokedAt.Valid {
		value := revokedAt.Time
		model.RevokedAt = &value
	}
	if replacedBy.Valid {
		value := replacedBy.Int64
		model.ReplacedByTokenID = &value
	}
	return &model, nil
}

func scanAccessToken(row scanner) (*tokendomain.AccessToken, error) {
	// access token 的 audience、user_id、revoked_at 都允许为空，因此这里统一做拆包。
	var model tokendomain.AccessToken
	var userID sql.NullInt64
	var revokedAt sql.NullTime
	var audienceJSON sql.NullString
	err := row.Scan(
		&model.ID,
		&model.TokenValue,
		&model.TokenSHA256,
		&model.ClientID,
		&userID,
		&model.Subject,
		&audienceJSON,
		&model.ScopesJSON,
		&model.TokenType,
		&model.TokenFormat,
		&model.IssuedAt,
		&model.ExpiresAt,
		&revokedAt,
		&model.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	if userID.Valid {
		value := userID.Int64
		model.UserID = &value
	}
	if revokedAt.Valid {
		value := revokedAt.Time
		model.RevokedAt = &value
	}
	if audienceJSON.Valid {
		model.AudienceJSON = audienceJSON.String
	}
	return &model, nil
}
