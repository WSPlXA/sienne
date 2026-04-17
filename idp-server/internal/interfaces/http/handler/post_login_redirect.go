package handler

import (
	"strings"

	pkgrbac "idp-server/pkg/rbac"
)

func resolveBrowserPostLoginRedirect(returnTo, upstreamRedirectURI, roleCode string) string {
	// 登录后浏览器跳转优先级：
	// 1. 显式 return_to；
	// 2. 上游认证流程指定的 redirect；
	// 3. 基于角色的后台默认入口。
	if target := strings.TrimSpace(returnTo); target != "" {
		return target
	}
	if target := strings.TrimSpace(upstreamRedirectURI); target != "" {
		return target
	}
	switch strings.ToLower(strings.TrimSpace(roleCode)) {
	case pkgrbac.RoleEndUser:
		return "/"
	case pkgrbac.RoleSupport:
		return "/admin/workbench/support"
	case pkgrbac.RoleOAuthAdmin:
		return "/admin/workbench/oauth"
	case pkgrbac.RoleSecurityAdmin:
		return "/admin/workbench/security"
	case pkgrbac.RoleSuperAdmin:
		return "/admin"
	default:
		return ""
	}
}
