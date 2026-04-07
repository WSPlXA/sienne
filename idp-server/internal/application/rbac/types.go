package rbac

import "errors"

var (
	ErrInvalidRoleCode     = errors.New("invalid role code")
	ErrRoleAlreadyExists   = errors.New("role already exists")
	ErrRoleNotFound        = errors.New("role not found")
	ErrSystemRoleImmutable = errors.New("system role is immutable")
	ErrRoleInUse           = errors.New("role is still assigned to users")
	ErrUserNotFound        = errors.New("user not found")
	ErrInvalidPrivilege    = errors.New("invalid privilege mask")
	ErrInvalidTenantScope  = errors.New("invalid tenant scope")
	ErrInvalidDisplayName  = errors.New("invalid display name")
	ErrInvalidDescription  = errors.New("invalid description")
)

type RoleView struct {
	RoleCode      string
	DisplayName   string
	Description   string
	PrivilegeMask uint32
	IsSystem      bool
}

type BootstrapRolesResult struct {
	Roles []RoleView
}

type ListRolesResult struct {
	Roles []RoleView
}

type AssignRoleInput struct {
	UserID        int64
	RoleCode      string
	PrivilegeMask *uint32
	TenantScope   string
}

type AssignRoleResult struct {
	UserID        int64
	Username      string
	RoleCode      string
	PrivilegeMask uint32
	TenantScope   string
}

type UpsertRoleInput struct {
	RoleCode      string
	DisplayName   string
	Description   string
	PrivilegeMask uint32
}

type DeleteRoleInput struct {
	RoleCode string
}

type RoleMutationResult struct {
	Role RoleView
}

type RoleUserView struct {
	UserID        int64  `json:"user_id"`
	UserUUID      string `json:"user_uuid"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name"`
	Status        string `json:"status"`
	RoleCode      string `json:"role_code"`
	PrivilegeMask uint32 `json:"privilege_mask"`
	TenantScope   string `json:"tenant_scope"`
}

type ListUsersByRoleInput struct {
	RoleCode string
	Limit    int
}

type ListUsersByRoleResult struct {
	RoleCode string
	Users    []RoleUserView
}

type RoleUsageView struct {
	RoleCode      string `json:"role_code"`
	DisplayName   string `json:"display_name"`
	IsSystem      bool   `json:"is_system"`
	PrivilegeMask uint32 `json:"privilege_mask"`
	UserCount     int64  `json:"user_count"`
}

type RoleUsageResult struct {
	Roles []RoleUsageView
}
