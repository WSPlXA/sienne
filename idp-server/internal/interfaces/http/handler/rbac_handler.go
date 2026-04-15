package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	apprbac "idp-server/internal/application/rbac"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/internal/ports/repository"

	"github.com/gin-gonic/gin"
)

type RBACHandler struct {
	service apprbac.Manager
	audit   repository.AuditEventRepository
}

func NewRBACHandler(service apprbac.Manager, audit repository.AuditEventRepository) *RBACHandler {
	return &RBACHandler{service: service, audit: audit}
}

func (h *RBACHandler) Bootstrap(c *gin.Context) {
	var req dto.LogoutRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid bootstrap request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		writeCSRFError(c)
		return
	}

	result, err := h.service.BootstrapBuiltinRoles(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "bootstrap roles failed"})
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.bootstrap", "rbac:bootstrap", map[string]any{
		"role_count": len(result.Roles),
	})
	c.JSON(http.StatusOK, gin.H{"roles": result.Roles})
}

func (h *RBACHandler) ListRoles(c *gin.Context) {
	result, err := h.service.ListRoles(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list roles failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"roles": result.Roles})
}

func (h *RBACHandler) ListUsersByRole(c *gin.Context) {
	limit := 100
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil {
			limit = value
		}
	}
	result, err := h.service.ListUsersByRole(c.Request.Context(), apprbac.ListUsersByRoleInput{
		RoleCode: c.Param("role_code"),
		Limit:    limit,
	})
	if err != nil {
		writeRBACError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"role_code": result.RoleCode,
		"users":     result.Users,
		"limit":     limit,
	})
}

func (h *RBACHandler) RoleUsage(c *gin.Context) {
	result, err := h.service.RoleUsage(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "role usage failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"roles": result.Roles})
}

func (h *RBACHandler) CreateRole(c *gin.Context) {
	var req dto.RoleMutationRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid create role request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		writeCSRFError(c)
		return
	}
	result, err := h.service.CreateRole(c.Request.Context(), apprbac.UpsertRoleInput{
		RoleCode:      req.RoleCode,
		DisplayName:   req.DisplayName,
		Description:   req.Description,
		PrivilegeMask: req.PrivilegeMask,
	})
	if err != nil {
		writeRBACError(c, err)
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.role.created", "role:"+result.Role.RoleCode, map[string]any{
		"role_code":      result.Role.RoleCode,
		"display_name":   result.Role.DisplayName,
		"privilege_mask": result.Role.PrivilegeMask,
		"is_system":      result.Role.IsSystem,
		"description":    result.Role.Description,
	})
	c.JSON(http.StatusCreated, gin.H{"role": result.Role})
}

func (h *RBACHandler) UpdateRole(c *gin.Context) {
	var req dto.RoleMutationRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid update role request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		writeCSRFError(c)
		return
	}
	result, err := h.service.UpdateRole(c.Request.Context(), apprbac.UpsertRoleInput{
		RoleCode:      c.Param("role_code"),
		DisplayName:   req.DisplayName,
		Description:   req.Description,
		PrivilegeMask: req.PrivilegeMask,
	})
	if err != nil {
		writeRBACError(c, err)
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.role.updated", "role:"+result.Role.RoleCode, map[string]any{
		"role_code":      result.Role.RoleCode,
		"display_name":   result.Role.DisplayName,
		"privilege_mask": result.Role.PrivilegeMask,
		"is_system":      result.Role.IsSystem,
		"description":    result.Role.Description,
	})
	c.JSON(http.StatusOK, gin.H{"role": result.Role})
}

func (h *RBACHandler) DeleteRole(c *gin.Context) {
	var req dto.LogoutRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid delete role request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		writeCSRFError(c)
		return
	}
	if err := h.service.DeleteRole(c.Request.Context(), apprbac.DeleteRoleInput{
		RoleCode: c.Param("role_code"),
	}); err != nil {
		writeRBACError(c, err)
		return
	}
	roleCode := strings.TrimSpace(c.Param("role_code"))
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.role.deleted", "role:"+roleCode, map[string]any{
		"role_code": roleCode,
	})
	c.JSON(http.StatusOK, gin.H{"deleted": true, "role_code": roleCode})
}

func (h *RBACHandler) AssignRole(c *gin.Context) {
	var req dto.AssignRoleRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid assign role request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		writeCSRFError(c)
		return
	}

	userID, err := strconv.ParseInt(strings.TrimSpace(c.Param("user_id")), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	result, err := h.service.AssignRole(c.Request.Context(), apprbac.AssignRoleInput{
		UserID:        userID,
		RoleCode:      req.RoleCode,
		PrivilegeMask: req.PrivilegeMask,
		TenantScope:   req.TenantScope,
	})
	if err != nil {
		var status int
		switch {
		case errors.Is(err, apprbac.ErrUserNotFound), errors.Is(err, apprbac.ErrRoleNotFound):
			status = http.StatusNotFound
		case errors.Is(err, apprbac.ErrInvalidRoleCode), errors.Is(err, apprbac.ErrInvalidPrivilege), errors.Is(err, apprbac.ErrInvalidTenantScope):
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	metadata := map[string]any{
		"user_id":        result.UserID,
		"username":       result.Username,
		"role_code":      result.RoleCode,
		"privilege_mask": result.PrivilegeMask,
		"tenant_scope":   result.TenantScope,
	}
	if req.PrivilegeMask != nil {
		metadata["custom_privilege_mask"] = true
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.role.assigned", "user:"+strconv.FormatInt(result.UserID, 10), metadata)

	c.JSON(http.StatusOK, gin.H{
		"user_id":        result.UserID,
		"username":       result.Username,
		"role_code":      result.RoleCode,
		"privilege_mask": result.PrivilegeMask,
		"tenant_scope":   result.TenantScope,
	})
}

func writeRBACError(c *gin.Context, err error) {
	var status int
	switch {
	case errors.Is(err, apprbac.ErrRoleAlreadyExists):
		status = http.StatusConflict
	case errors.Is(err, apprbac.ErrUserNotFound), errors.Is(err, apprbac.ErrRoleNotFound):
		status = http.StatusNotFound
	case errors.Is(err, apprbac.ErrRoleInUse):
		status = http.StatusConflict
	case errors.Is(err, apprbac.ErrSystemRoleImmutable):
		status = http.StatusForbidden
	case errors.Is(err, apprbac.ErrInvalidRoleCode),
		errors.Is(err, apprbac.ErrInvalidPrivilege),
		errors.Is(err, apprbac.ErrInvalidTenantScope),
		errors.Is(err, apprbac.ErrInvalidDisplayName),
		errors.Is(err, apprbac.ErrInvalidDescription):
		status = http.StatusBadRequest
	default:
		status = http.StatusInternalServerError
	}
	c.JSON(status, gin.H{"error": err.Error()})
}
