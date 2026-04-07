package persistence

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"idp-server/internal/domain/user"
	pkgrbac "idp-server/pkg/rbac"
)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, model *user.Model) error {
	roleCode := model.RoleCode
	if roleCode == "" {
		roleCode = pkgrbac.RoleEndUser
	}
	result, err := r.db.ExecContext(
		ctx,
		userRepositorySQL.createUser,
		model.UserUUID,
		model.Username,
		model.Email,
		model.EmailVerified,
		model.DisplayName,
		model.PasswordHash,
		roleCode,
		model.PrivilegeMask,
		nullString(model.TenantScope),
		model.Status,
		model.FailedLoginCount,
		nullTime(model.LastLoginAt),
	)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err == nil {
		model.ID = id
	}
	model.RoleCode = roleCode
	return nil
}

func (r *UserRepository) FindByID(ctx context.Context, id int64) (*user.Model, error) {
	return r.getOne(ctx, userRepositorySQL.findByID, id)
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*user.Model, error) {
	return r.getOne(ctx, userRepositorySQL.findByUsername, username)
}

func (r *UserRepository) ListByRoleCode(ctx context.Context, roleCode string, limit int) ([]*user.Model, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx, userRepositorySQL.listByRoleCode, roleCode, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*user.Model
	for rows.Next() {
		model, err := r.scanOne(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, model)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func (r *UserRepository) CountByRoleCode(ctx context.Context, roleCode string) (int64, error) {
	var count int64
	if err := r.db.QueryRowContext(ctx, userRepositorySQL.countByRoleCode, roleCode).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*user.Model, error) {
	return r.getOne(ctx, userRepositorySQL.findByEmail, email)
}

func (r *UserRepository) FindByUserUUID(ctx context.Context, userUUID string) (*user.Model, error) {
	return r.getOne(ctx, userRepositorySQL.findByUserUUID, userUUID)
}

func (r *UserRepository) UpdateRoleAndPrivilege(ctx context.Context, id int64, roleCode string, privilegeMask uint32, tenantScope string) error {
	_, err := r.db.ExecContext(ctx, userRepositorySQL.updateRoleAndPrivilege, roleCode, privilegeMask, nullString(tenantScope), id)
	return err
}

func (r *UserRepository) IncrementFailedLogin(ctx context.Context, id int64) (int64, error) {
	if _, err := r.db.ExecContext(ctx, userRepositorySQL.incrementFailedLogin, id); err != nil {
		return 0, err
	}

	var count int64
	if err := r.db.QueryRowContext(ctx, userRepositorySQL.selectFailedLoginCountByUserID, id).Scan(&count); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}

	return count, nil
}

func (r *UserRepository) ResetFailedLogin(ctx context.Context, id int64, lastLoginAt time.Time) error {
	_, err := r.db.ExecContext(ctx, userRepositorySQL.resetFailedLogin, lastLoginAt, id)
	return err
}

func (r *UserRepository) getOne(ctx context.Context, query string, arg any) (*user.Model, error) {
	row := r.db.QueryRowContext(ctx, query, arg)
	model, err := r.scanOne(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return model, nil
}

func (r *UserRepository) scanOne(scanner interface{ Scan(dest ...any) error }) (*user.Model, error) {
	var model user.Model
	var emailVerified bool
	var privilegeMask uint64
	var lastLoginAt sql.NullTime
	var tenantScope sql.NullString

	err := scanner.Scan(
		&model.ID,
		&model.UserUUID,
		&model.Username,
		&model.Email,
		&emailVerified,
		&model.DisplayName,
		&model.PasswordHash,
		&model.RoleCode,
		&privilegeMask,
		&tenantScope,
		&model.Status,
		&model.FailedLoginCount,
		&lastLoginAt,
		&model.CreatedAt,
		&model.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	model.EmailVerified = emailVerified
	model.PrivilegeMask = uint32(privilegeMask)
	if tenantScope.Valid {
		model.TenantScope = tenantScope.String
	}
	if lastLoginAt.Valid {
		t := lastLoginAt.Time
		model.LastLoginAt = &t
	}

	return &model, nil
}
