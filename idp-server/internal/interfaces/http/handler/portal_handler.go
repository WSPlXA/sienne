package handler

import (
	"net/http"

	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type PortalHandler struct{}

type portalDomainInfo struct {
	Name        string
	Bits        string
	Description string
}

type portalRoleCard struct {
	Title           string
	RoleCode        string
	DefaultMask     string
	RequiredAbility string
	EntryPath       string
}

type portalPageData struct {
	Domains []portalDomainInfo
	Roles   []portalRoleCard
}

type workbenchAction struct {
	Method   string
	Path     string
	Purpose  string
	Required string
}

type workbenchPageData struct {
	Title         string
	Subtitle      string
	CurrentUser   string
	CurrentRole   string
	PrivilegeMask uint32
	Actions       []workbenchAction
}

func NewPortalHandler() *PortalHandler {
	return &PortalHandler{}
}

func (h *PortalHandler) Home(c *gin.Context) {
	if !wantsHTML(c.GetHeader("Accept")) {
		c.JSON(http.StatusOK, gin.H{
			"message": "open '/' in browser for role-based routing portal",
			"entrypoints": []string{
				"/login",
				"/register",
				"/device",
				"/admin",
				"/admin/workbench/support",
				"/admin/workbench/oauth",
				"/admin/workbench/security",
			},
		})
		return
	}
	data := portalPageData{
		Domains: []portalDomainInfo{
			{Name: "AUTH", Bits: "[31..28]", Description: "login, session, MFA, challenge, lock status"},
			{Name: "OAUTH", Bits: "[27..24]", Description: "authorize, token, consent, device flow, introspect"},
			{Name: "CLIENT", Bits: "[23..20]", Description: "oauth clients, redirect URIs, grant types, secrets"},
			{Name: "USER", Bits: "[19..16]", Description: "user accounts, role assignment, account states"},
			{Name: "AUDIT", Bits: "[15..12]", Description: "security events and audit trails"},
			{Name: "KEY", Bits: "[11..8]", Description: "signing keys, JWKS, key rotation lifecycle"},
			{Name: "TENANT", Bits: "[7..4]", Description: "organization boundary and tenant scope"},
			{Name: "OPS", Bits: "[3..0]", Description: "platform controls and operational changes"},
		},
		Roles: []portalRoleCard{
			{Title: "End User Entry", RoleCode: "end_user", DefaultMask: "0x00000000", RequiredAbility: "basic login/session only", EntryPath: "/login"},
			{Title: "Support Workbench", RoleCode: "support", DefaultMask: "0xCC8C888C", RequiredAbility: "OPS.READ + USER.READ", EntryPath: "/admin/workbench/support"},
			{Title: "OAuth Workbench", RoleCode: "oauth_admin", DefaultMask: "0x8EEC8888", RequiredAbility: "OAUTH.READ + CLIENT.READ", EntryPath: "/admin/workbench/oauth"},
			{Title: "Security Workbench", RoleCode: "security_admin", DefaultMask: "0xEEEEEAEE", RequiredAbility: "AUDIT.READ + KEY.READ", EntryPath: "/admin/workbench/security"},
			{Title: "RBAC Console", RoleCode: "super_admin", DefaultMask: "0xFFFFFFFF", RequiredAbility: "OPS.READ (manage actions require OPS.MANAGE)", EntryPath: "/admin"},
		},
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = resource.PortalTemplate.Execute(c.Writer, data)
}

func (h *PortalHandler) SupportWorkbench(c *gin.Context) {
	h.renderWorkbench(c, workbenchPageData{
		Title:    "Support Workbench",
		Subtitle: "Read-first console for role usage checks and operational lookup.",
		Actions: []workbenchAction{
			{Method: "GET", Path: "/admin/rbac/usage", Purpose: "Check role usage counts before escalation.", Required: "OPS.READ"},
			{Method: "GET", Path: "/admin/rbac/roles", Purpose: "Inspect role definitions and masks.", Required: "OPS.READ"},
			{Method: "GET", Path: "/admin?role_code=support", Purpose: "Inspect users currently bound to support role.", Required: "OPS.READ"},
		},
	})
}

func (h *PortalHandler) OAuthWorkbench(c *gin.Context) {
	h.renderWorkbench(c, workbenchPageData{
		Title:    "OAuth Workbench",
		Subtitle: "Protocol-side operation panel for OAuth and OIDC endpoints.",
		Actions: []workbenchAction{
			{Method: "POST", Path: "/oauth2/clients", Purpose: "Create or onboard clients for apps/services.", Required: "CLIENT.MANAGE"},
			{Method: "POST", Path: "/oauth2/clients/:client_id/redirect-uris", Purpose: "Register callback URIs for authorization code flow.", Required: "CLIENT.MANAGE"},
			{Method: "GET", Path: "/.well-known/openid-configuration", Purpose: "Verify discovery metadata exposure.", Required: "OAUTH.READ"},
			{Method: "GET", Path: "/oauth2/jwks", Purpose: "Check issuer keyset used by downstream services.", Required: "OAUTH.READ"},
		},
	})
}

func (h *PortalHandler) SecurityWorkbench(c *gin.Context) {
	h.renderWorkbench(c, workbenchPageData{
		Title:    "Security Workbench",
		Subtitle: "Security controls for MFA assurance, introspection and high-risk reviews.",
		Actions: []workbenchAction{
			{Method: "GET", Path: "/mfa/totp/setup", Purpose: "Enroll or verify TOTP for the current operator account.", Required: "AUTH.EXEC"},
			{Method: "POST", Path: "/oauth2/introspect", Purpose: "Inspect token activity during incident response.", Required: "AUDIT.READ"},
			{Method: "POST", Path: "/admin/actions/users/logout-all", Purpose: "Force logout a compromised user account from all sessions.", Required: "USER.MANAGE + AUTH.EXEC"},
			{Method: "GET", Path: "/oauth2/jwks", Purpose: "Verify key rotation output for signing trust chain.", Required: "KEY.READ"},
		},
	})
}

func (h *PortalHandler) renderWorkbench(c *gin.Context, data workbenchPageData) {
	if adminUser := httpmiddleware.CurrentAdminUser(c); adminUser != nil {
		data.CurrentUser = adminUser.Username
		data.CurrentRole = adminUser.RoleCode
		data.PrivilegeMask = adminUser.PrivilegeMask
	}
	if !wantsHTML(c.GetHeader("Accept")) {
		c.JSON(http.StatusOK, data)
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = resource.WorkbenchTemplate.Execute(c.Writer, data)
}
