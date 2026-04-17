package persistence

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
)

type ConsentRepository struct {
	db dbRouter
}

func NewConsentRepository(db *sql.DB) *ConsentRepository {
	return NewConsentRepositoryRW(db, nil)
}

func NewConsentRepositoryRW(writeDB, readDB *sql.DB) *ConsentRepository {
	return &ConsentRepository{db: newDBRouter(writeDB, readDB)}
}

func (r *ConsentRepository) HasActiveConsent(ctx context.Context, userID, clientID int64, scopes []string) (bool, error) {
	var scopesJSON string
	err := r.db.reader().QueryRowContext(ctx, consentRepositorySQL.hasActiveConsentSelect, userID, clientID).Scan(&scopesJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}

	var grantedScopes []string
	if err := json.Unmarshal([]byte(scopesJSON), &grantedScopes); err != nil {
		return false, err
	}

	granted := make(map[string]struct{}, len(grantedScopes))
	for _, scope := range grantedScopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		granted[scope] = struct{}{}
	}

	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := granted[scope]; !ok {
			return false, nil
		}
	}

	return true, nil
}

func (r *ConsentRepository) UpsertActiveConsent(ctx context.Context, userID, clientID int64, scopes []string, grantedAt time.Time) error {
	tx, err := r.db.writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()

	var existingJSON string
	err = tx.QueryRowContext(ctx, consentRepositorySQL.upsertSelectExisting, userID, clientID).Scan(&existingJSON)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	scopeSet := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		scopeSet[scope] = struct{}{}
	}

	if err != sql.ErrNoRows && strings.TrimSpace(existingJSON) != "" {
		var existingScopes []string
		if unmarshalErr := json.Unmarshal([]byte(existingJSON), &existingScopes); unmarshalErr != nil {
			return unmarshalErr
		}
		for _, scope := range existingScopes {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			scopeSet[scope] = struct{}{}
		}
	}

	mergedScopes := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		mergedScopes = append(mergedScopes, scope)
	}

	scopesJSON, err := json.Marshal(mergedScopes)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, consentRepositorySQL.upsertActiveConsent, userID, clientID, string(scopesJSON), grantedAt); err != nil {
		return err
	}
	return tx.Commit()
}
