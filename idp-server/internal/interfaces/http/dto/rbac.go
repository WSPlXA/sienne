package dto

// AssignRoleRequest 描述把某个角色授予用户/主体时需要的输入。
// privilege_mask 允许在继承角色默认权限之外做额外收窄或扩展，
// tenant_scope 则把授权限定在某个租户/命名空间内。
type AssignRoleRequest struct {
	RoleCode      string  `json:"role_code" form:"role_code" binding:"required"`
	PrivilegeMask *uint32 `json:"privilege_mask" form:"privilege_mask"`
	TenantScope   string  `json:"tenant_scope" form:"tenant_scope"`
	CSRFToken     string  `json:"csrf_token" form:"csrf_token"`
}

// RoleMutationRequest 复用在创建/更新角色定义这类管理操作中。
// 它承载的是“角色模板”本身，而不是某次授予关系，因此 privilege mask
// 在这里表示角色默认具备的权限集合。
type RoleMutationRequest struct {
	RoleCode      string `json:"role_code" form:"role_code"`
	DisplayName   string `json:"display_name" form:"display_name" binding:"required"`
	Description   string `json:"description" form:"description" binding:"required"`
	PrivilegeMask uint32 `json:"privilege_mask" form:"privilege_mask" binding:"required"`
	CSRFToken     string `json:"csrf_token" form:"csrf_token"`
}
