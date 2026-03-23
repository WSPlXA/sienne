package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"idp-server/internal/domain/user"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, model *user.Model) error {
	const query = `
INSERT INTO users (
    user_uuid,
    username,
    email,
    email_verified,
    display_name,
    password_hash,
    status,
    failed_login_count,
    last_login_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := r.db.ExecContext(
		ctx,
		query,
		model.UserUUID,
		model.Username,
		model.Email,
		model.EmailVerified,
		model.DisplayName,
		model.PasswordHash,
		model.Status,
		model.FailedLoginCount,
		nullTime(model.LastLoginAt),
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

func (r *UserRepository) FindByID(ctx context.Context, id int64) (*user.Model, error) {
	const query = `
SELECT
    id,
    user_uuid,
    username,
    email,
    email_verified,
    display_name,
    password_hash,
    status,
    failed_login_count,
    last_login_at,
    created_at,
    updated_at
FROM users
WHERE id = ?
LIMIT 1`

	return r.getOne(ctx, query, id)
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*user.Model, error) {
	const query = `
SELECT
    id,
    user_uuid,
    username,
    email,
    email_verified,
    display_name,
    password_hash,
    status,
    failed_login_count,
    last_login_at,
    created_at,
    updated_at
FROM users
WHERE username = ?
LIMIT 1`

	return r.getOne(ctx, query, username)
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*user.Model, error) {
	const query = `
SELECT
    id,
    user_uuid,
    username,
    email,
    email_verified,
    display_name,
    password_hash,
    status,
    failed_login_count,
    last_login_at,
    created_at,
    updated_at
FROM users
WHERE email = ?
LIMIT 1`

	return r.getOne(ctx, query, email)
}

func (r *UserRepository) FindByUserUUID(ctx context.Context, userUUID string) (*user.Model, error) {
	const query = `
SELECT
    id,
    user_uuid,
    username,
    email,
    email_verified,
    display_name,
    password_hash,
    status,
    failed_login_count,
    last_login_at,
    created_at,
    updated_at
FROM users
WHERE user_uuid = ?
LIMIT 1`

	return r.getOne(ctx, query, userUUID)
}

func (r *UserRepository) IncrementFailedLogin(ctx context.Context, id int64) (int64, error) {
	const query = `
UPDATE users
SET failed_login_count = failed_login_count + 1
WHERE id = ?`

	if _, err := r.db.ExecContext(ctx, query, id); err != nil {
		return 0, err
	}

	const selectQuery = `
SELECT failed_login_count
FROM users
WHERE id = ?
LIMIT 1`

	var count int64
	if err := r.db.QueryRowContext(ctx, selectQuery, id).Scan(&count); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}

	return count, nil
}

func (r *UserRepository) ResetFailedLogin(ctx context.Context, id int64, lastLoginAt time.Time) error {
	const query = `
UPDATE users
SET failed_login_count = 0,
    last_login_at = ?
WHERE id = ?`

	_, err := r.db.ExecContext(ctx, query, lastLoginAt, id)
	return err
}

func (r *UserRepository) getOne(ctx context.Context, query string, arg any) (*user.Model, error) {
	var model user.Model
	var emailVerified bool
	var lastLoginAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, arg).Scan(
		&model.ID,
		&model.UserUUID,
		&model.Username,
		&model.Email,
		&emailVerified,
		&model.DisplayName,
		&model.PasswordHash,
		&model.Status,
		&model.FailedLoginCount,
		&lastLoginAt,
		&model.CreatedAt,
		&model.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	model.EmailVerified = emailVerified
	if lastLoginAt.Valid {
		t := lastLoginAt.Time
		model.LastLoginAt = &t
	}

	return &model, nil
}
