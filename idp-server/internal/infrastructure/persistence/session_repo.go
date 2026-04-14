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
	// session 持久化保存的是服务端会话真相来源；
	// Redis 只是性能优化层，不能替代数据库中的生命周期记录。
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
	// 单会话查询复用 getOne，统一处理 sql.ErrNoRows -> nil 的语义。
	return r.getOne(ctx, sessionRepositorySQL.findBySessionID, sessionID)
}

func (r *SessionRepository) ListActiveByUserID(ctx context.Context, userID int64) ([]*session.Model, error) {
	// 查询“某个用户当前所有活跃 session”是整用户登出的基础能力。
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
	// 退出时采用打时间戳标记，而不是删除记录，方便审计和问题追踪。
	_, err := r.db.ExecContext(ctx, sessionRepositorySQL.logoutBySessionID, loggedOutAt, sessionID)
	return err
}

func (r *SessionRepository) LogoutAllByUserID(ctx context.Context, userID int64, loggedOutAt time.Time) error {
	// 管理员强制下线和用户“退出全部设备”都会走到这条批量更新语句。
	_, err := r.db.ExecContext(ctx, sessionRepositorySQL.logoutAllByUserID, loggedOutAt, userID)
	return err
}

func (r *SessionRepository) getOne(ctx context.Context, query string, arg any) (*session.Model, error) {
	// getOne 把“没查到”转换成 nil 返回，减少上层仓储调用点的样板判断。
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
	// session 表里有多列 nullable 元数据（acr/amr/ip/userAgent/logoutAt），
	// 这里统一把它们展开成领域模型字段。
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
	// 写库辅助函数：空字符串按 NULL 处理，避免把“未知”与“明确为空”混在一起。
	if value == "" {
		return nil
	}
	return value
}

func nullTime(value *time.Time) any {
	// 指针为空时写 NULL，保留“尚未登出/尚未撤销”这类状态信息。
	if value == nil {
		return nil
	}
	return *value
}

func nullInt64(value *int64) any {
	// 某些 token/session 字段是可选外键，这里统一做 nullable 映射。
	if value == nil {
		return nil
	}
	return *value
}
