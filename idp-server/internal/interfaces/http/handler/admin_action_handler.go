package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	appclient "idp-server/internal/application/client"
	apprbac "idp-server/internal/application/rbac"
	appsession "idp-server/internal/application/session"
	"idp-server/internal/ports/repository"

	"github.com/gin-gonic/gin"
)

type AdminActionHandler struct {
	rbacService                     apprbac.Manager
	sessionService                  appsession.Manager
	clientCreator                   appclient.Creator
	clientRedirectRegistrar         appclient.Registrar
	clientPostLogoutRedirectManager appclient.PostLogoutRegistrar
	audit                           repository.AuditEventRepository
}

func NewAdminActionHandler(
	rbacService apprbac.Manager,
	sessionService appsession.Manager,
	clientCreator appclient.Creator,
	clientRedirectRegistrar appclient.Registrar,
	clientPostLogoutRedirectManager appclient.PostLogoutRegistrar,
	audit repository.AuditEventRepository,
) *AdminActionHandler {
	return &AdminActionHandler{
		rbacService:                     rbacService,
		sessionService:                  sessionService,
		clientCreator:                   clientCreator,
		clientRedirectRegistrar:         clientRedirectRegistrar,
		clientPostLogoutRedirectManager: clientPostLogoutRedirectManager,
		audit:                           audit,
	}
}

func (h *AdminActionHandler) BootstrapRoles(c *gin.Context) {
	if err := validateCSRFToken(c, c.PostForm("csrf_token")); err != nil {
		h.redirectWithError(c, errInvalidCSRFToken.Error())
		return
	}
	if h.rbacService == nil {
		h.redirectWithError(c, "rbac service unavailable")
		return
	}
	result, err := h.rbacService.BootstrapBuiltinRoles(c.Request.Context())
	if err != nil {
		h.redirectWithError(c, "bootstrap roles failed: "+err.Error())
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.bootstrap", "rbac:bootstrap", map[string]any{
		"role_count": len(result.Roles),
	})
	h.redirectWithNotice(c, "builtin roles have been bootstrapped")
}

func (h *AdminActionHandler) CreateRole(c *gin.Context) {
	if err := validateCSRFToken(c, c.PostForm("csrf_token")); err != nil {
		h.redirectWithError(c, errInvalidCSRFToken.Error())
		return
	}
	if h.rbacService == nil {
		h.redirectWithError(c, "rbac service unavailable")
		return
	}
	mask, err := parseUint32Field(c.PostForm("privilege_mask"), "privilege_mask")
	if err != nil {
		h.redirectWithError(c, err.Error())
		return
	}
	input := apprbac.UpsertRoleInput{
		RoleCode:      strings.TrimSpace(c.PostForm("role_code")),
		DisplayName:   strings.TrimSpace(c.PostForm("display_name")),
		Description:   strings.TrimSpace(c.PostForm("description")),
		PrivilegeMask: mask,
	}
	result, err := h.rbacService.CreateRole(c.Request.Context(), input)
	if err != nil {
		h.redirectWithError(c, "create role failed: "+err.Error())
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.role.created", "role:"+result.Role.RoleCode, map[string]any{
		"role_code":      result.Role.RoleCode,
		"display_name":   result.Role.DisplayName,
		"privilege_mask": result.Role.PrivilegeMask,
		"is_system":      result.Role.IsSystem,
	})
	h.redirectWithNotice(c, "role "+result.Role.RoleCode+" created")
}

func (h *AdminActionHandler) UpdateRole(c *gin.Context) {
	if err := validateCSRFToken(c, c.PostForm("csrf_token")); err != nil {
		h.redirectWithError(c, errInvalidCSRFToken.Error())
		return
	}
	if h.rbacService == nil {
		h.redirectWithError(c, "rbac service unavailable")
		return
	}
	mask, err := parseUint32Field(c.PostForm("privilege_mask"), "privilege_mask")
	if err != nil {
		h.redirectWithError(c, err.Error())
		return
	}
	input := apprbac.UpsertRoleInput{
		RoleCode:      strings.TrimSpace(c.PostForm("role_code")),
		DisplayName:   strings.TrimSpace(c.PostForm("display_name")),
		Description:   strings.TrimSpace(c.PostForm("description")),
		PrivilegeMask: mask,
	}
	result, err := h.rbacService.UpdateRole(c.Request.Context(), input)
	if err != nil {
		h.redirectWithError(c, "update role failed: "+err.Error())
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.role.updated", "role:"+result.Role.RoleCode, map[string]any{
		"role_code":      result.Role.RoleCode,
		"display_name":   result.Role.DisplayName,
		"privilege_mask": result.Role.PrivilegeMask,
		"is_system":      result.Role.IsSystem,
	})
	h.redirectWithNotice(c, "role "+result.Role.RoleCode+" updated")
}

func (h *AdminActionHandler) DeleteRole(c *gin.Context) {
	if err := validateCSRFToken(c, c.PostForm("csrf_token")); err != nil {
		h.redirectWithError(c, errInvalidCSRFToken.Error())
		return
	}
	if h.rbacService == nil {
		h.redirectWithError(c, "rbac service unavailable")
		return
	}
	roleCode := strings.TrimSpace(c.PostForm("role_code"))
	if err := h.rbacService.DeleteRole(c.Request.Context(), apprbac.DeleteRoleInput{
		RoleCode: roleCode,
	}); err != nil {
		h.redirectWithError(c, "delete role failed: "+err.Error())
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.role.deleted", "role:"+roleCode, map[string]any{
		"role_code": roleCode,
	})
	h.redirectWithNotice(c, "role "+roleCode+" deleted")
}

func (h *AdminActionHandler) AssignRole(c *gin.Context) {
	if err := validateCSRFToken(c, c.PostForm("csrf_token")); err != nil {
		h.redirectWithError(c, errInvalidCSRFToken.Error())
		return
	}
	if h.rbacService == nil {
		h.redirectWithError(c, "rbac service unavailable")
		return
	}
	userID, err := parseInt64Field(c.PostForm("user_id"), "user_id")
	if err != nil {
		h.redirectWithError(c, err.Error())
		return
	}
	var privilegeMask *uint32
	rawMask := strings.TrimSpace(c.PostForm("privilege_mask_custom"))
	if rawMask == "" {
		rawMask = strings.TrimSpace(c.PostForm("privilege_mask"))
	}
	if rawMask != "" {
		mask, err := parseUint32Field(rawMask, "privilege_mask")
		if err != nil {
			h.redirectWithError(c, err.Error())
			return
		}
		privilegeMask = &mask
	}
	result, err := h.rbacService.AssignRole(c.Request.Context(), apprbac.AssignRoleInput{
		UserID:        userID,
		RoleCode:      strings.TrimSpace(c.PostForm("role_code")),
		PrivilegeMask: privilegeMask,
		TenantScope:   strings.TrimSpace(c.PostForm("tenant_scope")),
	})
	if err != nil {
		h.redirectWithError(c, "assign role failed: "+err.Error())
		return
	}
	metadata := map[string]any{
		"user_id":        result.UserID,
		"username":       result.Username,
		"role_code":      result.RoleCode,
		"privilege_mask": result.PrivilegeMask,
		"tenant_scope":   result.TenantScope,
	}
	if privilegeMask != nil {
		metadata["custom_privilege_mask"] = true
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "rbac.role.assigned", "user:"+strconv.FormatInt(result.UserID, 10), metadata)
	h.redirectWithNotice(c, fmt.Sprintf("user %d assigned role %s", result.UserID, result.RoleCode))
}

func (h *AdminActionHandler) LogoutUser(c *gin.Context) {
	if err := validateCSRFToken(c, c.PostForm("csrf_token")); err != nil {
		h.redirectWithError(c, errInvalidCSRFToken.Error())
		return
	}
	if h.sessionService == nil {
		h.redirectWithError(c, "session service unavailable")
		return
	}
	userID, err := parseInt64Field(c.PostForm("user_id"), "user_id")
	if err != nil {
		h.redirectWithError(c, err.Error())
		return
	}
	result, err := h.sessionService.AdminLogoutUser(c.Request.Context(), appsession.AdminLogoutUserInput{
		UserID: userID,
	})
	if err != nil {
		h.redirectWithError(c, "logout user failed: "+err.Error())
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "auth.user.logout_all.admin", "user:"+result.UserID, map[string]any{
		"target_user_id":         result.UserID,
		"revoked_session_count":  result.RevokedSessionCount,
		"revoked_access_tokens":  result.RevokedAccessTokens,
		"revoked_refresh_tokens": result.RevokedRefreshTokens,
	})
	h.redirectWithNotice(c, fmt.Sprintf("user %d has been logged out from all sessions", userID))
}

func (h *AdminActionHandler) CreateOAuthClient(c *gin.Context) {
	if err := validateCSRFToken(c, c.PostForm("csrf_token")); err != nil {
		h.redirectWithError(c, errInvalidCSRFToken.Error())
		return
	}
	if h.clientCreator == nil {
		h.redirectWithError(c, "client service unavailable")
		return
	}

	grantTypes := parseDelimitedValues(c.PostForm("grant_types"))
	if len(grantTypes) == 0 {
		h.redirectWithError(c, "grant_types is required")
		return
	}
	scopes := parseDelimitedValues(c.PostForm("scopes"))
	if len(scopes) == 0 {
		h.redirectWithError(c, "scopes is required")
		return
	}
	requirePKCE, err := parseOptionalBoolField(c.PostForm("require_pkce"), "require_pkce")
	if err != nil {
		h.redirectWithError(c, err.Error())
		return
	}
	requireConsent, err := parseOptionalBoolField(c.PostForm("require_consent"), "require_consent")
	if err != nil {
		h.redirectWithError(c, err.Error())
		return
	}
	accessTTL, err := parseOptionalIntField(c.PostForm("access_token_ttl_seconds"), "access_token_ttl_seconds")
	if err != nil {
		h.redirectWithError(c, err.Error())
		return
	}
	refreshTTL, err := parseOptionalIntField(c.PostForm("refresh_token_ttl_seconds"), "refresh_token_ttl_seconds")
	if err != nil {
		h.redirectWithError(c, err.Error())
		return
	}
	idTokenTTL, err := parseOptionalIntField(c.PostForm("id_token_ttl_seconds"), "id_token_ttl_seconds")
	if err != nil {
		h.redirectWithError(c, err.Error())
		return
	}

	input := appclient.CreateClientInput{
		ClientID:                strings.TrimSpace(c.PostForm("client_id")),
		ClientName:              strings.TrimSpace(c.PostForm("client_name")),
		ClientSecret:            strings.TrimSpace(c.PostForm("client_secret")),
		ClientType:              strings.TrimSpace(c.PostForm("client_type")),
		TokenEndpointAuthMethod: strings.TrimSpace(c.PostForm("token_endpoint_auth_method")),
		RequirePKCE:             requirePKCE,
		RequireConsent:          requireConsent,
		AccessTokenTTLSeconds:   accessTTL,
		RefreshTokenTTLSeconds:  refreshTTL,
		IDTokenTTLSeconds:       idTokenTTL,
		GrantTypes:              grantTypes,
		Scopes:                  scopes,
		RedirectURIs:            parseDelimitedValues(c.PostForm("redirect_uris")),
		PostLogoutRedirectURIs:  parseDelimitedValues(c.PostForm("post_logout_redirect_uris")),
		Status:                  strings.TrimSpace(c.PostForm("status")),
	}
	result, err := h.clientCreator.CreateClient(c.Request.Context(), input)
	if err != nil {
		h.redirectWithError(c, "create oauth client failed: "+err.Error())
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "oauth.client.created", "client:"+result.ClientID, map[string]any{
		"client_id":     result.ClientID,
		"client_type":   result.ClientType,
		"grant_types":   result.GrantTypes,
		"redirect_uris": result.RedirectURIs,
	})
	h.redirectWithNotice(c, "oauth client "+result.ClientID+" created")
}

func (h *AdminActionHandler) RegisterClientRedirectURIs(c *gin.Context) {
	if err := validateCSRFToken(c, c.PostForm("csrf_token")); err != nil {
		h.redirectWithError(c, errInvalidCSRFToken.Error())
		return
	}
	if h.clientRedirectRegistrar == nil {
		h.redirectWithError(c, "redirect uri service unavailable")
		return
	}
	redirectURIs := parseDelimitedValues(c.PostForm("redirect_uris"))
	if len(redirectURIs) == 0 {
		h.redirectWithError(c, "redirect_uris is required")
		return
	}
	result, err := h.clientRedirectRegistrar.RegisterRedirectURIs(c.Request.Context(), appclient.RegisterRedirectURIsInput{
		ClientID:     strings.TrimSpace(c.PostForm("client_id")),
		RedirectURIs: redirectURIs,
	})
	if err != nil {
		h.redirectWithError(c, "register redirect uris failed: "+err.Error())
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "oauth.client.redirect_uris.registered", "client:"+result.ClientID, map[string]any{
		"client_id":        result.ClientID,
		"registered_count": result.RegisteredCount,
		"skipped_count":    result.SkippedCount,
	})
	h.redirectWithNotice(c, fmt.Sprintf("registered %d redirect uris for %s", result.RegisteredCount, result.ClientID))
}

func (h *AdminActionHandler) RegisterClientPostLogoutRedirectURIs(c *gin.Context) {
	if err := validateCSRFToken(c, c.PostForm("csrf_token")); err != nil {
		h.redirectWithError(c, errInvalidCSRFToken.Error())
		return
	}
	if h.clientPostLogoutRedirectManager == nil {
		h.redirectWithError(c, "post logout redirect service unavailable")
		return
	}
	redirectURIs := parseDelimitedValues(c.PostForm("post_logout_redirect_uris"))
	if len(redirectURIs) == 0 {
		h.redirectWithError(c, "post_logout_redirect_uris is required")
		return
	}
	result, err := h.clientPostLogoutRedirectManager.RegisterPostLogoutRedirectURIs(c.Request.Context(), appclient.RegisterPostLogoutRedirectURIsInput{
		ClientID:     strings.TrimSpace(c.PostForm("client_id")),
		RedirectURIs: redirectURIs,
	})
	if err != nil {
		h.redirectWithError(c, "register post logout redirect uris failed: "+err.Error())
		return
	}
	recordAdminAuditEvent(c.Request.Context(), h.audit, currentAdminAuditContext(c), "oauth.client.post_logout_redirect_uris.registered", "client:"+result.ClientID, map[string]any{
		"client_id":        result.ClientID,
		"registered_count": result.RegisteredCount,
		"skipped_count":    result.SkippedCount,
	})
	h.redirectWithNotice(c, fmt.Sprintf("registered %d post-logout redirect uris for %s", result.RegisteredCount, result.ClientID))
}

func (h *AdminActionHandler) redirectWithNotice(c *gin.Context, message string) {
	query := url.QueryEscape(strings.TrimSpace(message))
	c.Redirect(http.StatusFound, "/admin?notice="+query)
}

func (h *AdminActionHandler) redirectWithError(c *gin.Context, message string) {
	query := url.QueryEscape(strings.TrimSpace(message))
	c.Redirect(http.StatusFound, "/admin?error="+query)
}

func parseInt64Field(raw, field string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", field)
	}
	return value, nil
}

func parseUint32Field(raw, field string) (uint32, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("%s is required", field)
	}
	value, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		return 0, fmt.Errorf("%s must be an unsigned integer (decimal or 0x hex)", field)
	}
	return uint32(value), nil
}

func parseOptionalIntField(raw, field string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", field)
	}
	return value, nil
}

func parseOptionalBoolField(raw, field string) (*bool, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return nil, nil
	}
	switch raw {
	case "1", "true", "yes", "on":
		value := true
		return &value, nil
	case "0", "false", "no", "off":
		value := false
		return &value, nil
	default:
		return nil, fmt.Errorf("%s must be true/false", field)
	}
}

func parseDelimitedValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	})
	if len(parts) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(parts))
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}
