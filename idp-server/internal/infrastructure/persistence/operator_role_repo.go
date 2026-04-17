package persistence

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	operatorroledomain "idp-server/internal/domain/operatorrole"
)

type OperatorRoleRepository struct {
	db dbRouter
}

func NewOperatorRoleRepository(db *sql.DB) *OperatorRoleRepository {
	return NewOperatorRoleRepositoryRW(db, nil)
}

func NewOperatorRoleRepositoryRW(writeDB, readDB *sql.DB) *OperatorRoleRepository {
	return &OperatorRoleRepository{db: newDBRouter(writeDB, readDB)}
}

func (r *OperatorRoleRepository) Upsert(ctx context.Context, model *operatorroledomain.Model) error {
	result, err := r.db.writer().ExecContext(
		ctx,
		operatorRoleRepositorySQL.upsert,
		model.RoleCode,
		model.DisplayName,
		model.Description,
		model.PrivilegeMask,
		model.IsSystem,
	)
	if err != nil {
		return err
	}
	if id, err := result.LastInsertId(); err == nil && id > 0 {
		model.ID = id
	}
	return nil
}

func (r *OperatorRoleRepository) Create(ctx context.Context, model *operatorroledomain.Model) error {
	result, err := r.db.writer().ExecContext(
		ctx,
		operatorRoleRepositorySQL.create,
		model.RoleCode,
		model.DisplayName,
		model.Description,
		model.PrivilegeMask,
		model.IsSystem,
	)
	if err != nil {
		return err
	}
	if id, err := result.LastInsertId(); err == nil {
		model.ID = id
	}
	return nil
}

func (r *OperatorRoleRepository) Update(ctx context.Context, model *operatorroledomain.Model) error {
	_, err := r.db.writer().ExecContext(
		ctx,
		operatorRoleRepositorySQL.update,
		model.DisplayName,
		model.Description,
		model.PrivilegeMask,
		strings.TrimSpace(model.RoleCode),
	)
	return err
}

func (r *OperatorRoleRepository) DeleteByRoleCode(ctx context.Context, roleCode string) error {
	_, err := r.db.writer().ExecContext(ctx, operatorRoleRepositorySQL.deleteByRole, strings.TrimSpace(roleCode))
	return err
}

func (r *OperatorRoleRepository) FindByRoleCode(ctx context.Context, roleCode string) (*operatorroledomain.Model, error) {
	row := r.db.reader().QueryRowContext(ctx, operatorRoleRepositorySQL.findByRoleCode, roleCode)
	model, err := scanOperatorRole(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return model, nil
}

func (r *OperatorRoleRepository) List(ctx context.Context) ([]*operatorroledomain.Model, error) {
	rows, err := r.db.reader().QueryContext(ctx, operatorRoleRepositorySQL.list)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var roles []*operatorroledomain.Model
	for rows.Next() {
		model, err := scanOperatorRole(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, model)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return roles, nil
}

func scanOperatorRole(scanner interface{ Scan(dest ...any) error }) (*operatorroledomain.Model, error) {
	var model operatorroledomain.Model
	var privilegeMask uint64
	if err := scanner.Scan(
		&model.ID,
		&model.RoleCode,
		&model.DisplayName,
		&model.Description,
		&privilegeMask,
		&model.IsSystem,
		&model.CreatedAt,
		&model.UpdatedAt,
	); err != nil {
		return nil, err
	}
	model.PrivilegeMask = uint32(privilegeMask)
	return &model, nil
}
