package rbac

import (
	"context"
	"regexp"
	"strings"

	operatorroledomain "idp-server/internal/domain/operatorrole"
	"idp-server/internal/ports/repository"
	pkgrbac "idp-server/pkg/rbac"
)

type Manager interface {
	BootstrapBuiltinRoles(ctx context.Context) (*BootstrapRolesResult, error)
	ListRoles(ctx context.Context) (*ListRolesResult, error)
	ListUsersByRole(ctx context.Context, input ListUsersByRoleInput) (*ListUsersByRoleResult, error)
	RoleUsage(ctx context.Context) (*RoleUsageResult, error)
	AssignRole(ctx context.Context, input AssignRoleInput) (*AssignRoleResult, error)
	CreateRole(ctx context.Context, input UpsertRoleInput) (*RoleMutationResult, error)
	UpdateRole(ctx context.Context, input UpsertRoleInput) (*RoleMutationResult, error)
	DeleteRole(ctx context.Context, input DeleteRoleInput) error
}

type Service struct {
	roles repository.OperatorRoleRepository
	users repository.UserRepository
}

var roleCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_:-]{2,63}$`)

func NewService(roles repository.OperatorRoleRepository, users repository.UserRepository) *Service {
	return &Service{
		roles: roles,
		users: users,
	}
}

func (s *Service) BootstrapBuiltinRoles(ctx context.Context) (*BootstrapRolesResult, error) {
	builtin := builtinRoles()
	for _, role := range builtin {
		roleCopy := role
		if err := s.roles.Upsert(ctx, &roleCopy); err != nil {
			return nil, err
		}
	}
	return &BootstrapRolesResult{Roles: builtinRoleViews()}, nil
}

func (s *Service) ListRoles(ctx context.Context) (*ListRolesResult, error) {
	models, err := s.roles.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]RoleView, 0, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		result = append(result, RoleView{
			RoleCode:      model.RoleCode,
			DisplayName:   model.DisplayName,
			Description:   model.Description,
			PrivilegeMask: model.PrivilegeMask,
			IsSystem:      model.IsSystem,
		})
	}
	return &ListRolesResult{Roles: result}, nil
}

func (s *Service) ListUsersByRole(ctx context.Context, input ListUsersByRoleInput) (*ListUsersByRoleResult, error) {
	roleCode := strings.TrimSpace(input.RoleCode)
	if !roleCodePattern.MatchString(roleCode) {
		return nil, ErrInvalidRoleCode
	}
	role, err := s.roles.FindByRoleCode(ctx, roleCode)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, ErrRoleNotFound
	}
	users, err := s.users.ListByRoleCode(ctx, roleCode, input.Limit)
	if err != nil {
		return nil, err
	}
	result := make([]RoleUserView, 0, len(users))
	for _, user := range users {
		if user == nil {
			continue
		}
		result = append(result, RoleUserView{
			UserID:        user.ID,
			UserUUID:      user.UserUUID,
			Username:      user.Username,
			Email:         user.Email,
			DisplayName:   user.DisplayName,
			Status:        user.Status,
			RoleCode:      user.RoleCode,
			PrivilegeMask: user.PrivilegeMask,
			TenantScope:   user.TenantScope,
		})
	}
	return &ListUsersByRoleResult{
		RoleCode: roleCode,
		Users:    result,
	}, nil
}

func (s *Service) RoleUsage(ctx context.Context) (*RoleUsageResult, error) {
	roles, err := s.roles.List(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]RoleUsageView, 0, len(roles))
	for _, role := range roles {
		if role == nil {
			continue
		}
		count, err := s.users.CountByRoleCode(ctx, role.RoleCode)
		if err != nil {
			return nil, err
		}
		result = append(result, RoleUsageView{
			RoleCode:      role.RoleCode,
			DisplayName:   role.DisplayName,
			IsSystem:      role.IsSystem,
			PrivilegeMask: role.PrivilegeMask,
			UserCount:     count,
		})
	}
	return &RoleUsageResult{Roles: result}, nil
}

func (s *Service) AssignRole(ctx context.Context, input AssignRoleInput) (*AssignRoleResult, error) {
	if input.UserID <= 0 {
		return nil, ErrUserNotFound
	}
	roleCode := strings.TrimSpace(input.RoleCode)
	if roleCode == "" {
		return nil, ErrInvalidRoleCode
	}
	if len(input.TenantScope) > 128 {
		return nil, ErrInvalidTenantScope
	}

	user, err := s.users.FindByID(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	role, err := s.roles.FindByRoleCode(ctx, roleCode)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, ErrRoleNotFound
	}

	mask := role.PrivilegeMask
	if input.PrivilegeMask != nil {
		mask = *input.PrivilegeMask
	}
	if err := s.users.UpdateRoleAndPrivilege(ctx, input.UserID, roleCode, mask, strings.TrimSpace(input.TenantScope)); err != nil {
		return nil, err
	}

	return &AssignRoleResult{
		UserID:        user.ID,
		Username:      user.Username,
		RoleCode:      roleCode,
		PrivilegeMask: mask,
		TenantScope:   strings.TrimSpace(input.TenantScope),
	}, nil
}

func (s *Service) CreateRole(ctx context.Context, input UpsertRoleInput) (*RoleMutationResult, error) {
	roleCode, err := normalizeRoleInput(input)
	if err != nil {
		return nil, err
	}
	existing, err := s.roles.FindByRoleCode(ctx, roleCode)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrRoleAlreadyExists
	}

	model := &operatorroledomain.Model{
		RoleCode:      roleCode,
		DisplayName:   strings.TrimSpace(input.DisplayName),
		Description:   strings.TrimSpace(input.Description),
		PrivilegeMask: input.PrivilegeMask,
		IsSystem:      false,
	}
	if err := s.roles.Create(ctx, model); err != nil {
		return nil, err
	}
	return &RoleMutationResult{Role: toRoleView(model)}, nil
}

func (s *Service) UpdateRole(ctx context.Context, input UpsertRoleInput) (*RoleMutationResult, error) {
	roleCode, err := normalizeRoleInput(input)
	if err != nil {
		return nil, err
	}
	existing, err := s.roles.FindByRoleCode(ctx, roleCode)
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, ErrRoleNotFound
	}
	if existing.IsSystem {
		return nil, ErrSystemRoleImmutable
	}

	existing.DisplayName = strings.TrimSpace(input.DisplayName)
	existing.Description = strings.TrimSpace(input.Description)
	existing.PrivilegeMask = input.PrivilegeMask
	if err := s.roles.Update(ctx, existing); err != nil {
		return nil, err
	}
	return &RoleMutationResult{Role: toRoleView(existing)}, nil
}

func (s *Service) DeleteRole(ctx context.Context, input DeleteRoleInput) error {
	roleCode := strings.TrimSpace(input.RoleCode)
	if !roleCodePattern.MatchString(roleCode) {
		return ErrInvalidRoleCode
	}
	existing, err := s.roles.FindByRoleCode(ctx, roleCode)
	if err != nil {
		return err
	}
	if existing == nil {
		return ErrRoleNotFound
	}
	if existing.IsSystem {
		return ErrSystemRoleImmutable
	}
	count, err := s.users.CountByRoleCode(ctx, roleCode)
	if err != nil {
		return err
	}
	if count > 0 {
		return ErrRoleInUse
	}
	return s.roles.DeleteByRoleCode(ctx, roleCode)
}

func builtinRoles() []operatorroledomain.Model {
	return []operatorroledomain.Model{
		{
			RoleCode:      pkgrbac.RoleEndUser,
			DisplayName:   "End User",
			Description:   "regular end user without management privilege",
			PrivilegeMask: pkgrbac.MaskEndUser,
			IsSystem:      true,
		},
		{
			RoleCode:      pkgrbac.RoleSupport,
			DisplayName:   "Support Engineer",
			Description:   "support operator with read and limited execution permissions",
			PrivilegeMask: pkgrbac.MaskSupport,
			IsSystem:      true,
		},
		{
			RoleCode:      pkgrbac.RoleOAuthAdmin,
			DisplayName:   "OAuth Administrator",
			Description:   "operator managing oauth clients and protocol settings",
			PrivilegeMask: pkgrbac.MaskOAuthAdmin,
			IsSystem:      true,
		},
		{
			RoleCode:      pkgrbac.RoleSecurityAdmin,
			DisplayName:   "Security Administrator",
			Description:   "security operator with broad but not catastrophic security permissions",
			PrivilegeMask: pkgrbac.MaskSecurityAdmin,
			IsSystem:      true,
		},
		{
			RoleCode:      pkgrbac.RoleSuperAdmin,
			DisplayName:   "Super Administrator",
			Description:   "full access operator for bootstrap and emergency operations",
			PrivilegeMask: pkgrbac.MaskSuperAdmin,
			IsSystem:      true,
		},
	}
}

func builtinRoleViews() []RoleView {
	roles := builtinRoles()
	result := make([]RoleView, 0, len(roles))
	for _, role := range roles {
		result = append(result, RoleView{
			RoleCode:      role.RoleCode,
			DisplayName:   role.DisplayName,
			Description:   role.Description,
			PrivilegeMask: role.PrivilegeMask,
			IsSystem:      role.IsSystem,
		})
	}
	return result
}

func normalizeRoleInput(input UpsertRoleInput) (string, error) {
	roleCode := strings.TrimSpace(input.RoleCode)
	displayName := strings.TrimSpace(input.DisplayName)
	description := strings.TrimSpace(input.Description)

	switch {
	case !roleCodePattern.MatchString(roleCode):
		return "", ErrInvalidRoleCode
	case len(displayName) < 2 || len(displayName) > 128:
		return "", ErrInvalidDisplayName
	case len(description) < 4 || len(description) > 512:
		return "", ErrInvalidDescription
	default:
		_ = input.PrivilegeMask
		return roleCode, nil
	}
}

func toRoleView(model *operatorroledomain.Model) RoleView {
	return RoleView{
		RoleCode:      model.RoleCode,
		DisplayName:   model.DisplayName,
		Description:   model.Description,
		PrivilegeMask: model.PrivilegeMask,
		IsSystem:      model.IsSystem,
	}
}
