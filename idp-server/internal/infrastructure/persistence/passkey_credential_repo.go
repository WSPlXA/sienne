package persistence

import (
	"context"
	"database/sql"
	"time"

	passkeydomain "idp-server/internal/domain/passkey"
)

type PasskeyCredentialRepository struct {
	db dbRouter
}

func NewPasskeyCredentialRepository(db *sql.DB) *PasskeyCredentialRepository {
	return NewPasskeyCredentialRepositoryRW(db, nil)
}

func NewPasskeyCredentialRepositoryRW(writeDB, readDB *sql.DB) *PasskeyCredentialRepository {
	return &PasskeyCredentialRepository{db: newDBRouter(writeDB, readDB)}
}

func (r *PasskeyCredentialRepository) ListByUserID(ctx context.Context, userID int64) ([]*passkeydomain.Model, error) {
	rows, err := r.db.reader().QueryContext(ctx, passkeyCredentialRepositorySQL.listByUserID, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var result []*passkeydomain.Model
	for rows.Next() {
		model, err := r.scanOne(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, model)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *PasskeyCredentialRepository) Upsert(ctx context.Context, model *passkeydomain.Model) error {
	now := time.Now().UTC()
	if model.CreatedAt.IsZero() {
		model.CreatedAt = now
	}
	if model.UpdatedAt.IsZero() {
		model.UpdatedAt = now
	}
	var lastUsed any
	if model.LastUsedAt != nil {
		lastUsed = *model.LastUsedAt
	}
	_, err := r.db.writer().ExecContext(
		ctx,
		passkeyCredentialRepositorySQL.upsert,
		model.UserID,
		model.CredentialID,
		model.CredentialJSON,
		lastUsed,
		model.CreatedAt,
		model.UpdatedAt,
	)
	return err
}

func (r *PasskeyCredentialRepository) TouchByCredentialID(ctx context.Context, credentialID string, lastUsedAt time.Time) error {
	_, err := r.db.writer().ExecContext(ctx, passkeyCredentialRepositorySQL.touchByCredentialID, lastUsedAt, credentialID)
	return err
}

func (r *PasskeyCredentialRepository) scanOne(scanner interface{ Scan(dest ...any) error }) (*passkeydomain.Model, error) {
	var model passkeydomain.Model
	var lastUsedAt sql.NullTime
	err := scanner.Scan(
		&model.ID,
		&model.UserID,
		&model.CredentialID,
		&model.CredentialJSON,
		&lastUsedAt,
		&model.CreatedAt,
		&model.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if lastUsedAt.Valid {
		t := lastUsedAt.Time
		model.LastUsedAt = &t
	}
	return &model, nil
}
