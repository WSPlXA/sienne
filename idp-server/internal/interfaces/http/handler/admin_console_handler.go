package handler

import (
	"fmt"
	"net/http"
	"strings"

	apprbac "idp-server/internal/application/rbac"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	"idp-server/internal/ports/repository"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type AdminConsoleHandler struct {
	rbacService apprbac.Manager
	users       repository.UserRepository
}

type adminConsolePageData struct {
	Username         string
	RoleCode         string
	PrivilegeMask    uint32
	TenantScope      string
	Roles            []apprbac.RoleView
	PrivilegePresets []adminPrivilegePreset
	Usage            []apprbac.RoleUsageView
	LookupRole       string
	LookupUsers      []apprbac.RoleUserView
	LookupUsername   string
	LookupUser       *adminUserLookupView
	LookupUserError  string
	CSRFToken        string
	Notice           string
	Error            string
}

type adminUserLookupView struct {
	UserID        int64
	UserUUID      string
	Username      string
	Email         string
	DisplayName   string
	Status        string
	RoleCode      string
	PrivilegeMask uint32
	TenantScope   string
}

type adminPrivilegePreset struct {
	Label       string
	Value       string
	Composition string
}

func NewAdminConsoleHandler(rbacService apprbac.Manager, users repository.UserRepository) *AdminConsoleHandler {
	return &AdminConsoleHandler{rbacService: rbacService, users: users}
}

func (h *AdminConsoleHandler) Handle(c *gin.Context) {
	if h.rbacService == nil {
		h.writeError(c, http.StatusServiceUnavailable, "rbac service unavailable", adminConsolePageData{})
		return
	}

	adminUser := httpmiddleware.CurrentAdminUser(c)
	data := adminConsolePageData{}
	if adminUser != nil {
		data.Username = adminUser.Username
		data.RoleCode = adminUser.RoleCode
		data.PrivilegeMask = adminUser.PrivilegeMask
		data.TenantScope = adminUser.TenantScope
	}
	data.Notice = strings.TrimSpace(c.Query("notice"))
	data.Error = strings.TrimSpace(c.Query("error"))
	if csrfToken, err := ensureCSRFToken(c); err == nil {
		data.CSRFToken = csrfToken
	}

	rolesResult, err := h.rbacService.ListRoles(c.Request.Context())
	if err != nil {
		h.writeError(c, http.StatusInternalServerError, "failed to load roles", data)
		return
	}
	if rolesResult != nil {
		data.Roles = rolesResult.Roles
		data.PrivilegePresets = buildPrivilegePresets(rolesResult.Roles)
	}

	usageResult, err := h.rbacService.RoleUsage(c.Request.Context())
	if err != nil {
		h.writeError(c, http.StatusInternalServerError, "failed to load role usage", data)
		return
	}
	if usageResult != nil {
		data.Usage = usageResult.Roles
	}
	if roleCode := strings.TrimSpace(c.Query("role_code")); roleCode != "" {
		usersResult, err := h.rbacService.ListUsersByRole(c.Request.Context(), apprbac.ListUsersByRoleInput{
			RoleCode: roleCode,
			Limit:    100,
		})
		if err != nil {
			data.Error = "failed to load users by role: " + err.Error()
			data.LookupRole = roleCode
		} else if usersResult != nil {
			data.LookupRole = usersResult.RoleCode
			data.LookupUsers = usersResult.Users
		}
	}
	if lookupUsername := strings.TrimSpace(c.Query("lookup_username")); lookupUsername != "" {
		data.LookupUsername = lookupUsername
		if h.users == nil {
			data.LookupUserError = "user lookup service unavailable"
		} else {
			userModel, err := h.users.FindByUsername(c.Request.Context(), lookupUsername)
			if err != nil {
				data.LookupUserError = "failed to lookup user: " + err.Error()
			} else if userModel == nil {
				data.LookupUserError = "user not found: " + lookupUsername
			} else {
				data.LookupUser = &adminUserLookupView{
					UserID:        userModel.ID,
					UserUUID:      userModel.UserUUID,
					Username:      userModel.Username,
					Email:         userModel.Email,
					DisplayName:   userModel.DisplayName,
					Status:        userModel.Status,
					RoleCode:      userModel.RoleCode,
					PrivilegeMask: userModel.PrivilegeMask,
					TenantScope:   userModel.TenantScope,
				}
			}
		}
	}

	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(http.StatusOK)
		_ = resource.AdminConsoleTemplate.Execute(c.Writer, data)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"operator": gin.H{
			"username":       data.Username,
			"role_code":      data.RoleCode,
			"privilege_mask": data.PrivilegeMask,
			"tenant_scope":   data.TenantScope,
		},
		"roles":             data.Roles,
		"privilege_presets": data.PrivilegePresets,
		"role_usage":        data.Usage,
		"lookup_role":       data.LookupRole,
		"lookup_users":      data.LookupUsers,
		"lookup_username":   data.LookupUsername,
		"lookup_user":       data.LookupUser,
		"lookup_user_error": data.LookupUserError,
		"notice":            data.Notice,
		"csrf_issued":       data.CSRFToken != "",
		"error_message":     data.Error,
	})
}

func buildPrivilegePresets(roles []apprbac.RoleView) []adminPrivilegePreset {
	if len(roles) == 0 {
		return nil
	}
	result := make([]adminPrivilegePreset, 0, len(roles))
	for _, role := range roles {
		label := strings.TrimSpace(role.RoleCode)
		if displayName := strings.TrimSpace(role.DisplayName); displayName != "" && !strings.EqualFold(displayName, label) {
			label += " (" + displayName + ")"
		}
		result = append(result, adminPrivilegePreset{
			Label:       label,
			Value:       fmt.Sprintf("0x%08X", role.PrivilegeMask),
			Composition: formatPrivilegeComposition(role.PrivilegeMask),
		})
	}
	return result
}

func formatPrivilegeComposition(mask uint32) string {
	type domainBit struct {
		name  string
		shift uint
	}
	type actionBit struct {
		name string
		bit  uint32
	}
	domains := []domainBit{
		{name: "AUTH", shift: 28},
		{name: "OAUTH", shift: 24},
		{name: "CLIENT", shift: 20},
		{name: "USER", shift: 16},
		{name: "AUDIT", shift: 12},
		{name: "KEY", shift: 8},
		{name: "TENANT", shift: 4},
		{name: "OPS", shift: 0},
	}
	actions := []actionBit{
		{name: "READ", bit: 0x8},
		{name: "EXEC", bit: 0x4},
		{name: "MANAGE", bit: 0x2},
		{name: "PRIV", bit: 0x1},
	}

	segments := make([]string, 0, len(domains))
	for _, domain := range domains {
		nibble := (mask >> domain.shift) & 0xF
		if nibble == 0 {
			continue
		}
		setActions := make([]string, 0, len(actions))
		for _, action := range actions {
			if nibble&action.bit == action.bit {
				setActions = append(setActions, action.name)
			}
		}
		if len(setActions) == 0 {
			continue
		}
		segments = append(segments, domain.name+":"+strings.Join(setActions, "+"))
	}
	if len(segments) == 0 {
		return "NONE"
	}
	return strings.Join(segments, "; ")
}

func (h *AdminConsoleHandler) writeError(c *gin.Context, status int, message string, data adminConsolePageData) {
	if wantsHTML(c.GetHeader("Accept")) {
		data.Error = message
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.AdminConsoleTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, gin.H{"error": message})
}
