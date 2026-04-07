package dto

type AssignRoleRequest struct {
	RoleCode      string  `json:"role_code" form:"role_code" binding:"required"`
	PrivilegeMask *uint32 `json:"privilege_mask" form:"privilege_mask"`
	TenantScope   string  `json:"tenant_scope" form:"tenant_scope"`
	CSRFToken     string  `json:"csrf_token" form:"csrf_token"`
}

type RoleMutationRequest struct {
	RoleCode      string `json:"role_code" form:"role_code"`
	DisplayName   string `json:"display_name" form:"display_name" binding:"required"`
	Description   string `json:"description" form:"description" binding:"required"`
	PrivilegeMask uint32 `json:"privilege_mask" form:"privilege_mask" binding:"required"`
	CSRFToken     string `json:"csrf_token" form:"csrf_token"`
}
