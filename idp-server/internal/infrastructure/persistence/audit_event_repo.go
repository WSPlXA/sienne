package persistence

import (
	"context"
	"database/sql"
	"strings"

	auditdomain "idp-server/internal/domain/audit"
)

type AuditEventRepository struct {
	db *sql.DB
}

func NewAuditEventRepository(db *sql.DB) *AuditEventRepository {
	return &AuditEventRepository{db: db}
}

func (r *AuditEventRepository) Create(ctx context.Context, model *auditdomain.Model) error {
	var clientID any
	if model.ClientID != nil && *model.ClientID > 0 {
		clientID = *model.ClientID
	}

	var userID any
	if model.UserID != nil && *model.UserID > 0 {
		userID = *model.UserID
	}

	var sessionID any
	if model.SessionID != nil && *model.SessionID > 0 {
		sessionID = *model.SessionID
	}

	var metadata any
	if strings.TrimSpace(model.MetadataJSON) != "" {
		metadata = model.MetadataJSON
	}

	result, err := r.db.ExecContext(
		ctx,
		auditEventRepositorySQL.create,
		strings.TrimSpace(model.EventType),
		clientID,
		userID,
		strings.TrimSpace(model.Subject),
		sessionID,
		strings.TrimSpace(model.IPAddress),
		strings.TrimSpace(model.UserAgent),
		metadata,
	)
	if err != nil {
		return err
	}
	if id, err := result.LastInsertId(); err == nil {
		model.ID = id
	}
	return nil
}
