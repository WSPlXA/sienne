package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"idp-server/internal/domain/session"
)

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, model *session.Model) error {
	result, err := r.db.ExecContext(
		ctx,
		sessionRepositorySQL.createSession,
		model.SessionID,
		model.UserID,
		model.Subject,
		nullString(model.ACR),
		nullString(model.AMRJSON),
		nullString(model.IPAddress),
		nullString(model.UserAgent),
		model.AuthenticatedAt,
		model.ExpiresAt,
		nullTime(model.LoggedOutAt),
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

func (r *SessionRepository) FindBySessionID(ctx context.Context, sessionID string) (*session.Model, error) {
	return r.getOne(ctx, sessionRepositorySQL.findBySessionID, sessionID)
}

func (r *SessionRepository) ListActiveByUserID(ctx context.Context, userID int64) ([]*session.Model, error) {
	rows, err := r.db.QueryContext(ctx, sessionRepositorySQL.listActiveByUserID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*session.Model
	for rows.Next() {
		model, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, model)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}

func (r *SessionRepository) LogoutBySessionID(ctx context.Context, sessionID string, loggedOutAt time.Time) error {
	_, err := r.db.ExecContext(ctx, sessionRepositorySQL.logoutBySessionID, loggedOutAt, sessionID)
	return err
}

func (r *SessionRepository) LogoutAllByUserID(ctx context.Context, userID int64, loggedOutAt time.Time) error {
	_, err := r.db.ExecContext(ctx, sessionRepositorySQL.logoutAllByUserID, loggedOutAt, userID)
	return err
}

func (r *SessionRepository) getOne(ctx context.Context, query string, arg any) (*session.Model, error) {
	row := r.db.QueryRowContext(ctx, query, arg)
	model, err := scanSession(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return model, nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanSession(s scanner) (*session.Model, error) {
	var model session.Model
	var acr sql.NullString
	var amrJSON sql.NullString
	var ipAddress sql.NullString
	var userAgent sql.NullString
	var loggedOutAt sql.NullTime

	err := s.Scan(
		&model.ID,
		&model.SessionID,
		&model.UserID,
		&model.Subject,
		&acr,
		&amrJSON,
		&ipAddress,
		&userAgent,
		&model.AuthenticatedAt,
		&model.ExpiresAt,
		&loggedOutAt,
		&model.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	model.ACR = acr.String
	model.AMRJSON = amrJSON.String
	model.IPAddress = ipAddress.String
	model.UserAgent = userAgent.String
	if loggedOutAt.Valid {
		t := loggedOutAt.Time
		model.LoggedOutAt = &t
	}

	return &model, nil
}

func nullString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}
