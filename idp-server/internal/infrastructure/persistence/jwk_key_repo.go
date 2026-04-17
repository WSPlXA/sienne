package persistence

import (
	"context"
	"database/sql"
	"time"
)

type JWKKeyRecord struct {
	ID            int64
	KID           string
	KTY           string
	Alg           string
	UseType       string
	PublicJWKJSON string
	PrivateKeyRef string
	IsActive      bool
	CreatedAt     time.Time
	RotatesAt     *time.Time
	DeactivatedAt *time.Time
}

type JWKKeyRepository struct {
	db dbRouter
}

func NewJWKKeyRepository(db *sql.DB) *JWKKeyRepository {
	return NewJWKKeyRepositoryRW(db, nil)
}

func NewJWKKeyRepositoryRW(writeDB, readDB *sql.DB) *JWKKeyRepository {
	return &JWKKeyRepository{db: newDBRouter(writeDB, readDB)}
}

func (r *JWKKeyRepository) ListCurrent(ctx context.Context) ([]JWKKeyRecord, error) {
	rows, err := r.db.writer().QueryContext(ctx, jwkKeyRepositorySQL.listCurrentKeys)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var records []JWKKeyRecord
	for rows.Next() {
		var record JWKKeyRecord
		var privateKeyRef sql.NullString
		var rotatesAt sql.NullTime
		var deactivatedAt sql.NullTime
		if err := rows.Scan(
			&record.ID,
			&record.KID,
			&record.KTY,
			&record.Alg,
			&record.UseType,
			&record.PublicJWKJSON,
			&privateKeyRef,
			&record.IsActive,
			&record.CreatedAt,
			&rotatesAt,
			&deactivatedAt,
		); err != nil {
			return nil, err
		}
		record.PrivateKeyRef = privateKeyRef.String
		if rotatesAt.Valid {
			value := rotatesAt.Time
			record.RotatesAt = &value
		}
		if deactivatedAt.Valid {
			value := deactivatedAt.Time
			record.DeactivatedAt = &value
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return records, nil
}

func (r *JWKKeyRepository) CreateActiveKey(ctx context.Context, record JWKKeyRecord, retiresExistingAt time.Time) error {
	tx, err := r.db.writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(ctx, jwkKeyRepositorySQL.deactivateActive, retiresExistingAt, retiresExistingAt); err != nil {
		return err
	}

	_, err = tx.ExecContext(
		ctx,
		jwkKeyRepositorySQL.insertActiveKey,
		record.KID,
		record.KTY,
		record.Alg,
		record.UseType,
		record.PublicJWKJSON,
		nullString(record.PrivateKeyRef),
		record.CreatedAt,
		nullTime(record.RotatesAt),
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}
