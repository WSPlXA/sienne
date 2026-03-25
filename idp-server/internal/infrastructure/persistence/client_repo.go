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
	db *sql.DB
}

func NewClientRepository(db *sql.DB) *ClientRepository {
	return &ClientRepository{db: db}
}

func (r *ClientRepository) CreateClient(ctx context.Context, model *clientdomain.Model) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	const clientQuery = `
INSERT INTO oauth_clients (
    client_id,
    client_name,
    client_secret_hash,
    client_type,
    token_endpoint_auth_method,
    require_pkce,
    require_consent,
    access_token_ttl_seconds,
    refresh_token_ttl_seconds,
    id_token_ttl_seconds,
    status
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := tx.ExecContext(
		ctx,
		clientQuery,
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

	if err := insertStringValuesTx(ctx, tx, `INSERT INTO oauth_client_grant_types (client_id, grant_type) VALUES (?, ?)`, model.ID, model.GrantTypes); err != nil {
		return err
	}
	if err := insertStringValuesTx(ctx, tx, `INSERT INTO oauth_client_auth_methods (client_id, auth_method) VALUES (?, ?)`, model.ID, model.AuthMethods); err != nil {
		return err
	}
	if err := insertStringValuesTx(ctx, tx, `INSERT INTO oauth_client_scopes (client_id, scope) VALUES (?, ?)`, model.ID, model.Scopes); err != nil {
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
	const query = `
SELECT
    id,
    client_id,
    client_name,
    client_secret_hash,
    client_type,
    token_endpoint_auth_method,
    require_pkce,
    require_consent,
    access_token_ttl_seconds,
    refresh_token_ttl_seconds,
    id_token_ttl_seconds,
    status,
    created_at,
    updated_at
FROM oauth_clients
WHERE client_id = ?
LIMIT 1`

	var model clientdomain.Model
	var secretHash sql.NullString
	err := r.db.QueryRowContext(ctx, query, clientID).Scan(
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
	model.RedirectURIs, loadErr = r.loadStrings(ctx, `SELECT redirect_uri FROM oauth_client_redirect_uris WHERE client_id = ? ORDER BY id`, model.ID)
	if loadErr != nil {
		return nil, loadErr
	}
	model.GrantTypes, loadErr = r.loadStrings(ctx, `SELECT grant_type FROM oauth_client_grant_types WHERE client_id = ? ORDER BY id`, model.ID)
	if loadErr != nil {
		return nil, loadErr
	}
	model.AuthMethods, loadErr = r.loadStrings(ctx, `SELECT auth_method FROM oauth_client_auth_methods WHERE client_id = ? ORDER BY id`, model.ID)
	if loadErr != nil {
		return nil, loadErr
	}
	model.Scopes, loadErr = r.loadStrings(ctx, `SELECT scope FROM oauth_client_scopes WHERE client_id = ? ORDER BY id`, model.ID)
	if loadErr != nil {
		return nil, loadErr
	}

	return &model, nil
}

func (r *ClientRepository) loadStrings(ctx context.Context, query string, clientID int64) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

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

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	const query = `
INSERT IGNORE INTO oauth_client_redirect_uris (
    client_id,
    redirect_uri,
    redirect_uri_sha256
) VALUES (?, ?, ?)`

	insertedCount := 0
	for _, redirectURI := range redirectURIs {
		hash := sha256.Sum256([]byte(redirectURI))
		result, execErr := tx.ExecContext(ctx, query, clientDBID, redirectURI, hex.EncodeToString(hash[:]))
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
	const query = `
SELECT 1
FROM oauth_client_post_logout_redirect_uris
WHERE client_id = ? AND redirect_uri_sha256 = ?
LIMIT 1`

	hash := sha256.Sum256([]byte(redirectURI))
	var matched int
	err := r.db.QueryRowContext(ctx, query, clientDBID, hex.EncodeToString(hash[:])).Scan(&matched)
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

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	const query = `
INSERT IGNORE INTO oauth_client_post_logout_redirect_uris (
    client_id,
    redirect_uri,
    redirect_uri_sha256
) VALUES (?, ?, ?)`

	insertedCount := 0
	for _, redirectURI := range redirectURIs {
		hash := sha256.Sum256([]byte(redirectURI))
		result, execErr := tx.ExecContext(ctx, query, clientDBID, redirectURI, hex.EncodeToString(hash[:]))
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
	const query = `
INSERT INTO oauth_client_redirect_uris (
    client_id,
    redirect_uri,
    redirect_uri_sha256
) VALUES (?, ?, ?)`

	for _, redirectURI := range redirectURIs {
		hash := sha256.Sum256([]byte(redirectURI))
		if _, err := tx.ExecContext(ctx, query, clientDBID, redirectURI, hex.EncodeToString(hash[:])); err != nil {
			return err
		}
	}
	return nil
}

func insertPostLogoutRedirectURIsTx(ctx context.Context, tx *sql.Tx, clientDBID int64, redirectURIs []string) error {
	if len(redirectURIs) == 0 {
		return nil
	}

	const query = `
INSERT INTO oauth_client_post_logout_redirect_uris (
    client_id,
    redirect_uri,
    redirect_uri_sha256
) VALUES (?, ?, ?)`

	for _, redirectURI := range redirectURIs {
		hash := sha256.Sum256([]byte(redirectURI))
		if _, err := tx.ExecContext(ctx, query, clientDBID, redirectURI, hex.EncodeToString(hash[:])); err != nil {
			return err
		}
	}
	return nil
}
