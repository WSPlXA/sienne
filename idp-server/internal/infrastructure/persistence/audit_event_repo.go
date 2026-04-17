package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	auditdomain "idp-server/internal/domain/audit"
	repositoryport "idp-server/internal/ports/repository"

	"github.com/google/uuid"
)

type AuditEventRepository struct {
	db dbRouter
}

func NewAuditEventRepository(db *sql.DB) *AuditEventRepository {
	return NewAuditEventRepositoryRW(db, nil)
}

func NewAuditEventRepositoryRW(writeDB, readDB *sql.DB) *AuditEventRepository {
	return &AuditEventRepository{db: newDBRouter(writeDB, readDB)}
}

func (r *AuditEventRepository) Create(ctx context.Context, model *auditdomain.Model) error {
	if strings.TrimSpace(model.EventID) == "" {
		model.EventID = uuid.NewString()
	}

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

	result, err := r.db.writer().ExecContext(
		ctx,
		auditEventRepositorySQL.create,
		strings.TrimSpace(model.EventID),
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

func (r *AuditEventRepository) List(ctx context.Context, input repositoryport.ListAuditEventsInput) ([]*auditdomain.Model, error) {
	limit := input.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	offset := input.Offset
	if offset < 0 {
		offset = 0
	}

	queryBuilder := strings.Builder{}
	queryBuilder.WriteString(auditEventRepositorySQL.listBase)

	args := make([]any, 0, 8)
	conditions := make([]string, 0, 6)
	if eventType := strings.TrimSpace(input.EventType); eventType != "" {
		conditions = append(conditions, "event_type = ?")
		args = append(args, eventType)
	}
	if input.UserID != nil && *input.UserID > 0 {
		conditions = append(conditions, "user_id = ?")
		args = append(args, *input.UserID)
	}
	if subject := strings.TrimSpace(input.Subject); subject != "" {
		conditions = append(conditions, "subject LIKE ?")
		args = append(args, "%"+subject+"%")
	}
	if input.From != nil {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, *input.From)
	}
	if input.To != nil {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, *input.To)
	}
	if len(conditions) > 0 {
		queryBuilder.WriteString(" WHERE ")
		queryBuilder.WriteString(strings.Join(conditions, " AND "))
	}
	queryBuilder.WriteString(" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?")
	args = append(args, limit, offset)

	rows, err := r.db.reader().QueryContext(ctx, queryBuilder.String(), args...)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	events := make([]*auditdomain.Model, 0, limit)
	for rows.Next() {
		var model auditdomain.Model
		var eventID sql.NullString
		var clientID sql.NullInt64
		var userID sql.NullInt64
		var sessionID sql.NullInt64
		var subject sql.NullString
		var ipAddress sql.NullString
		var userAgent sql.NullString
		var metadata sql.NullString
		if err := rows.Scan(
			&model.ID,
			&eventID,
			&model.EventType,
			&clientID,
			&userID,
			&subject,
			&sessionID,
			&ipAddress,
			&userAgent,
			&metadata,
			&model.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		model.EventID = strings.TrimSpace(eventID.String)
		if clientID.Valid {
			value := clientID.Int64
			model.ClientID = &value
		}
		if userID.Valid {
			value := userID.Int64
			model.UserID = &value
		}
		if sessionID.Valid {
			value := sessionID.Int64
			model.SessionID = &value
		}
		model.Subject = subject.String
		model.IPAddress = ipAddress.String
		model.UserAgent = userAgent.String
		model.MetadataJSON = strings.TrimSpace(metadata.String)
		events = append(events, &model)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}
	return events, nil
}
