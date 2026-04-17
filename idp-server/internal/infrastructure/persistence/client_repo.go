package persistence

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"

	clientdomain "idp-server/internal/domain/client"
)

type ClientRepository struct {
	db dbRouter
}

func NewClientRepository(db *sql.DB) *ClientRepository {
	return NewClientRepositoryRW(db, nil)
}

func NewClientRepositoryRW(writeDB, readDB *sql.DB) *ClientRepository {
	return &ClientRepository{db: newDBRouter(writeDB, readDB)}
}

func (r *ClientRepository) CreateClient(ctx context.Context, model *clientdomain.Model) error {
	tx, err := r.db.writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	result, err := tx.ExecContext(
		ctx,
		clientRepositorySQL.createClient,
		model.ClientID,
		model.ClientName,
		nullString(model.ClientSecretHash),
		model.ClientType,
		model.TokenEndpointAuthMethod,
		model.RequirePKCE,
		model.RequireConsent,
		model.AccessTokenTTLSeconds,
		model.RefreshTokenTTLSeconds,
		model.IDTokenTTLSeconds,
		model.Status,
	)
	if err != nil {
		return err
	}

	insertedID, err := result.LastInsertId()
	if err != nil {
		return err
	}
	model.ID = insertedID

	if err := insertStringValuesTx(ctx, tx, clientRepositorySQL.insertClientGrantType, model.ID, model.GrantTypes); err != nil {
		return err
	}
	if err := insertStringValuesTx(ctx, tx, clientRepositorySQL.insertClientAuthMethod, model.ID, model.AuthMethods); err != nil {
		return err
	}
	if err := insertStringValuesTx(ctx, tx, clientRepositorySQL.insertClientScope, model.ID, model.Scopes); err != nil {
		return err
	}
	if err := insertRedirectURIsTx(ctx, tx, model.ID, model.RedirectURIs); err != nil {
		return err
	}
	if err := insertPostLogoutRedirectURIsTx(ctx, tx, model.ID, model.PostLogoutRedirectURIs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	tx = nil
	return nil
}

func (r *ClientRepository) FindByClientID(ctx context.Context, clientID string) (*clientdomain.Model, error) {
	var model clientdomain.Model
	var secretHash sql.NullString
	err := r.db.reader().QueryRowContext(ctx, clientRepositorySQL.findByClientID, clientID).Scan(
		&model.ID,
		&model.ClientID,
		&model.ClientName,
		&secretHash,
		&model.ClientType,
		&model.TokenEndpointAuthMethod,
		&model.RequirePKCE,
		&model.RequireConsent,
		&model.AccessTokenTTLSeconds,
		&model.RefreshTokenTTLSeconds,
		&model.IDTokenTTLSeconds,
		&model.Status,
		&model.CreatedAt,
		&model.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	model.ClientSecretHash = secretHash.String

	var loadErr error
	model.RedirectURIs, loadErr = r.loadStrings(ctx, clientRepositorySQL.selectRedirectURIsByClientID, model.ID)
	if loadErr != nil {
		return nil, loadErr
	}
	model.GrantTypes, loadErr = r.loadStrings(ctx, clientRepositorySQL.selectGrantTypesByClientID, model.ID)
	if loadErr != nil {
		return nil, loadErr
	}
	model.AuthMethods, loadErr = r.loadStrings(ctx, clientRepositorySQL.selectAuthMethodsByClientID, model.ID)
	if loadErr != nil {
		return nil, loadErr
	}
	model.Scopes, loadErr = r.loadStrings(ctx, clientRepositorySQL.selectScopesByClientID, model.ID)
	if loadErr != nil {
		return nil, loadErr
	}

	return &model, nil
}

func (r *ClientRepository) loadStrings(ctx context.Context, query string, clientID int64) ([]string, error) {
	rows, err := r.db.reader().QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func (r *ClientRepository) RegisterRedirectURIs(ctx context.Context, clientDBID int64, redirectURIs []string) (int, error) {
	if len(redirectURIs) == 0 {
		return 0, nil
	}

	tx, err := r.db.writer().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	insertedCount := 0
	for _, redirectURI := range redirectURIs {
		hash := sha256.Sum256([]byte(redirectURI))
		result, execErr := tx.ExecContext(ctx, clientRepositorySQL.insertRedirectURIIgnore, clientDBID, redirectURI, hex.EncodeToString(hash[:]))
		if execErr != nil {
			return 0, execErr
		}

		affectedRows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return 0, rowsErr
		}
		insertedCount += int(affectedRows)
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	tx = nil

	return insertedCount, nil
}

func (r *ClientRepository) HasPostLogoutRedirectURI(ctx context.Context, clientDBID int64, redirectURI string) (bool, error) {
	hash := sha256.Sum256([]byte(redirectURI))
	var matched int
	err := r.db.reader().QueryRowContext(ctx, clientRepositorySQL.hasPostLogoutRedirectURI, clientDBID, hex.EncodeToString(hash[:])).Scan(&matched)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return matched == 1, nil
}

func (r *ClientRepository) RegisterPostLogoutRedirectURIs(ctx context.Context, clientDBID int64, redirectURIs []string) (int, error) {
	if len(redirectURIs) == 0 {
		return 0, nil
	}

	tx, err := r.db.writer().BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	insertedCount := 0
	for _, redirectURI := range redirectURIs {
		hash := sha256.Sum256([]byte(redirectURI))
		result, execErr := tx.ExecContext(ctx, clientRepositorySQL.insertPostLogoutRedirectURIIgnore, clientDBID, redirectURI, hex.EncodeToString(hash[:]))
		if execErr != nil {
			return 0, execErr
		}

		affectedRows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return 0, rowsErr
		}
		insertedCount += int(affectedRows)
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	tx = nil

	return insertedCount, nil
}

func insertStringValuesTx(ctx context.Context, tx *sql.Tx, query string, clientDBID int64, values []string) error {
	for _, value := range values {
		if _, err := tx.ExecContext(ctx, query, clientDBID, value); err != nil {
			return err
		}
	}
	return nil
}

func insertRedirectURIsTx(ctx context.Context, tx *sql.Tx, clientDBID int64, redirectURIs []string) error {
	for _, redirectURI := range redirectURIs {
		hash := sha256.Sum256([]byte(redirectURI))
		if _, err := tx.ExecContext(ctx, clientRepositorySQL.insertRedirectURI, clientDBID, redirectURI, hex.EncodeToString(hash[:])); err != nil {
			return err
		}
	}
	return nil
}

func insertPostLogoutRedirectURIsTx(ctx context.Context, tx *sql.Tx, clientDBID int64, redirectURIs []string) error {
	if len(redirectURIs) == 0 {
		return nil
	}

	for _, redirectURI := range redirectURIs {
		hash := sha256.Sum256([]byte(redirectURI))
		if _, err := tx.ExecContext(ctx, clientRepositorySQL.insertPostLogoutRedirectURI, clientDBID, redirectURI, hex.EncodeToString(hash[:])); err != nil {
			return err
		}
	}
	return nil
}
