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
	const query = `
INSERT INTO oauth_access_tokens (
    token_value,
    token_sha256,
    client_id,
    user_id,
    subject,
    audience_json,
    scopes_json,
    token_type,
    token_format,
    issued_at,
    expires_at,
    revoked_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(
		ctx,
		query,
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
	const query = `
INSERT INTO oauth_refresh_tokens (
    token_value,
    token_sha256,
    client_id,
    user_id,
    subject,
    scopes_json,
    issued_at,
    expires_at,
    revoked_at,
    replaced_by_token_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(
		ctx,
		query,
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
	const query = `
SELECT
    id,
    token_value,
    token_sha256,
    client_id,
    user_id,
    subject,
    audience_json,
    scopes_json,
    token_type,
    token_format,
    issued_at,
    expires_at,
    revoked_at,
    created_at
FROM oauth_access_tokens
WHERE token_sha256 = ?
  AND revoked_at IS NULL
  AND expires_at > CURRENT_TIMESTAMP
LIMIT 1`

	row := r.db.QueryRowContext(ctx, query, tokenSHA256)
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
	const query = `
SELECT
    id,
    token_value,
    token_sha256,
    client_id,
    user_id,
    subject,
    scopes_json,
    issued_at,
    expires_at,
    revoked_at,
    replaced_by_token_id,
    created_at
FROM oauth_refresh_tokens
WHERE token_sha256 = ?
  AND revoked_at IS NULL
  AND replaced_by_token_id IS NULL
  AND expires_at > CURRENT_TIMESTAMP
LIMIT 1`

	row := r.db.QueryRowContext(ctx, query, tokenSHA256)
	model, err := scanRefreshToken(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return model, nil
}

func (r *TokenRepository) RotateRefreshToken(ctx context.Context, oldTokenSHA256 string, revokedAt time.Time, newToken *tokendomain.RefreshToken) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	const oldQuery = `
SELECT
    id,
    token_value,
    token_sha256,
    client_id,
    user_id,
    subject,
    scopes_json,
    issued_at,
    expires_at,
    revoked_at,
    replaced_by_token_id,
    created_at
FROM oauth_refresh_tokens
WHERE token_sha256 = ?
FOR UPDATE`

	oldToken, err := scanRefreshToken(tx.QueryRowContext(ctx, oldQuery, oldTokenSHA256))
	if err != nil {
		return err
	}

	const insertQuery = `
INSERT INTO oauth_refresh_tokens (
    token_value,
    token_sha256,
    client_id,
    user_id,
    subject,
    scopes_json,
    issued_at,
    expires_at,
    revoked_at,
    replaced_by_token_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := tx.ExecContext(
		ctx,
		insertQuery,
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

	const updateQuery = `
UPDATE oauth_refresh_tokens
SET revoked_at = ?, replaced_by_token_id = ?
WHERE id = ?`
	if _, err := tx.ExecContext(ctx, updateQuery, revokedAt, newToken.ID, oldToken.ID); err != nil {
		return err
	}

	return tx.Commit()
}

func scanRefreshToken(row scanner) (*tokendomain.RefreshToken, error) {
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
