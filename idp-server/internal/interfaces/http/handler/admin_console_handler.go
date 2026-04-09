package handler

import (
	"net/http"
	"strings"

	apprbac "idp-server/internal/application/rbac"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type AdminConsoleHandler struct {
	rbacService apprbac.Manager
}

type adminConsolePageData struct {
	Username      string
	RoleCode      string
	PrivilegeMask uint32
	TenantScope   string
	Roles         []apprbac.RoleView
	Usage         []apprbac.RoleUsageView
	LookupRole    string
	LookupUsers   []apprbac.RoleUserView
	CSRFToken     string
	Notice        string
	Error         string
}

func NewAdminConsoleHandler(rbacService apprbac.Manager) *AdminConsoleHandler {
	return &AdminConsoleHandler{rbacService: rbacService}
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
		"roles":         data.Roles,
		"role_usage":    data.Usage,
		"lookup_role":   data.LookupRole,
		"lookup_users":  data.LookupUsers,
		"notice":        data.Notice,
		"csrf_issued":   data.CSRFToken != "",
		"error_message": data.Error,
	})
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
