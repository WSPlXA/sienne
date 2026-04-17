package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	totpdomain "idp-server/internal/domain/totp"
)

type TOTPRepository struct {
	db    dbRouter
	codec secretCodec
}

type secretCodec interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(value string) (string, error)
}

func NewTOTPRepository(db *sql.DB, codec secretCodec) *TOTPRepository {
	return NewTOTPRepositoryRW(db, nil, codec)
}

func NewTOTPRepositoryRW(writeDB, readDB *sql.DB, codec secretCodec) *TOTPRepository {
	return &TOTPRepository{db: newDBRouter(writeDB, readDB), codec: codec}
}

func (r *TOTPRepository) FindByUserID(ctx context.Context, userID int64) (*totpdomain.Model, error) {
	var model totpdomain.Model
	err := r.db.reader().QueryRowContext(ctx, totpRepositorySQL.findByUserID, userID).Scan(
		&model.ID,
		&model.UserID,
		&model.Secret,
		&model.EnabledAt,
		&model.CreatedAt,
		&model.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	secret, err := r.decryptSecret(model.Secret)
	if err != nil {
		return nil, err
	}
	model.Secret = secret
	return &model, nil
}

func (r *TOTPRepository) Upsert(ctx context.Context, model *totpdomain.Model) error {
	now := time.Now().UTC()
	if model.CreatedAt.IsZero() {
		model.CreatedAt = now
	}
	if model.UpdatedAt.IsZero() {
		model.UpdatedAt = now
	}
	if model.EnabledAt.IsZero() {
		model.EnabledAt = now
	}
	secret, err := r.encryptSecret(model.Secret)
	if err != nil {
		return err
	}
	_, err = r.db.writer().ExecContext(ctx, totpRepositorySQL.upsert, model.UserID, secret, model.EnabledAt, model.CreatedAt, model.UpdatedAt)
	return err
}

func (r *TOTPRepository) encryptSecret(secret string) (string, error) {
	if r.codec == nil {
		return secret, nil
	}
	return r.codec.Encrypt(secret)
}

func (r *TOTPRepository) decryptSecret(secret string) (string, error) {
	if r.codec == nil {
		return secret, nil
	}
	return r.codec.Decrypt(secret)
}

func (r *TOTPRepository) DeleteByUserID(ctx context.Context, userID int64) error {
	_, err := r.db.writer().ExecContext(ctx, totpRepositorySQL.deleteByUser, userID)
	return err
}
