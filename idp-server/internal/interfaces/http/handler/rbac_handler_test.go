package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	apprbac "idp-server/internal/application/rbac"

	"github.com/gin-gonic/gin"
)

type stubRBACManager struct {
	assignInput apprbac.AssignRoleInput
	createInput apprbac.UpsertRoleInput
	updateInput apprbac.UpsertRoleInput
	deleteInput apprbac.DeleteRoleInput
}

func (s *stubRBACManager) BootstrapBuiltinRoles(context.Context) (*apprbac.BootstrapRolesResult, error) {
	return &apprbac.BootstrapRolesResult{Roles: []apprbac.RoleView{{RoleCode: "super_admin", PrivilegeMask: 0xFFFFFFFF}}}, nil
}

func (s *stubRBACManager) ListRoles(context.Context) (*apprbac.ListRolesResult, error) {
	return &apprbac.ListRolesResult{Roles: []apprbac.RoleView{{RoleCode: "support", PrivilegeMask: 3431757964}}}, nil
}

func (s *stubRBACManager) ListUsersByRole(_ context.Context, input apprbac.ListUsersByRoleInput) (*apprbac.ListUsersByRoleResult, error) {
	return &apprbac.ListUsersByRoleResult{
		RoleCode: input.RoleCode,
		Users: []apprbac.RoleUserView{
			{UserID: 1, Username: "alice", RoleCode: input.RoleCode},
		},
	}, nil
}

func (s *stubRBACManager) RoleUsage(context.Context) (*apprbac.RoleUsageResult, error) {
	return &apprbac.RoleUsageResult{
		Roles: []apprbac.RoleUsageView{
			{RoleCode: "support", UserCount: 1},
		},
	}, nil
}

func (s *stubRBACManager) AssignRole(_ context.Context, input apprbac.AssignRoleInput) (*apprbac.AssignRoleResult, error) {
	s.assignInput = input
	return &apprbac.AssignRoleResult{
		UserID:        input.UserID,
		Username:      "alice",
		RoleCode:      input.RoleCode,
		PrivilegeMask: derefMask(input.PrivilegeMask, 0),
		TenantScope:   input.TenantScope,
	}, nil
}

func (s *stubRBACManager) CreateRole(_ context.Context, input apprbac.UpsertRoleInput) (*apprbac.RoleMutationResult, error) {
	s.createInput = input
	return &apprbac.RoleMutationResult{Role: apprbac.RoleView{RoleCode: input.RoleCode, DisplayName: input.DisplayName, Description: input.Description, PrivilegeMask: input.PrivilegeMask}}, nil
}

func (s *stubRBACManager) UpdateRole(_ context.Context, input apprbac.UpsertRoleInput) (*apprbac.RoleMutationResult, error) {
	s.updateInput = input
	return &apprbac.RoleMutationResult{Role: apprbac.RoleView{RoleCode: input.RoleCode, DisplayName: input.DisplayName, Description: input.Description, PrivilegeMask: input.PrivilegeMask}}, nil
}

func (s *stubRBACManager) DeleteRole(_ context.Context, input apprbac.DeleteRoleInput) error {
	s.deleteInput = input
	return nil
}

func derefMask(value *uint32, fallback uint32) uint32 {
	if value == nil {
		return fallback
	}
	return *value
}

func TestRBACHandlerListRoles(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/admin/rbac/roles", NewRBACHandler(&stubRBACManager{}).ListRoles)
	req := httptest.NewRequest(http.MethodGet, "/admin/rbac/roles", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRBACHandlerAssignRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubRBACManager{}
	router := gin.New()
	router.POST("/admin/users/:user_id/role", NewRBACHandler(service).AssignRole)
	csrfCookie, csrfToken := mustNewCSRFCookie(t)

	form := url.Values{}
	form.Set("role_code", "support")
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/admin/users/42/role", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if service.assignInput.UserID != 42 || service.assignInput.RoleCode != "support" {
		t.Fatalf("assign input = %#v", service.assignInput)
	}
}

func TestRBACHandlerCreateRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubRBACManager{}
	router := gin.New()
	router.POST("/admin/rbac/roles", NewRBACHandler(service).CreateRole)
	csrfCookie, csrfToken := mustNewCSRFCookie(t)

	form := url.Values{}
	form.Set("role_code", "custom_ops")
	form.Set("display_name", "Custom Ops")
	form.Set("description", "custom operations role")
	form.Set("privilege_mask", "14")
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/admin/rbac/roles", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusCreated)
	}
	if service.createInput.RoleCode != "custom_ops" {
		t.Fatalf("create input = %#v", service.createInput)
	}
}

func TestRBACHandlerDeleteRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubRBACManager{}
	router := gin.New()
	router.DELETE("/admin/rbac/roles/:role_code", NewRBACHandler(service).DeleteRole)
	csrfCookie, csrfToken := mustNewCSRFCookie(t)

	form := url.Values{}
	form.Set("csrf_token", csrfToken)
	req := httptest.NewRequest(http.MethodDelete, "/admin/rbac/roles/custom_ops", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set(csrfHeaderName, csrfToken)
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if service.deleteInput.RoleCode != "custom_ops" {
		t.Fatalf("delete input = %#v", service.deleteInput)
	}
}

func TestRBACHandlerListUsersByRole(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/admin/rbac/roles/:role_code/users", NewRBACHandler(&stubRBACManager{}).ListUsersByRole)
	req := httptest.NewRequest(http.MethodGet, "/admin/rbac/roles/support/users?limit=10", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRBACHandlerRoleUsage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/admin/rbac/usage", NewRBACHandler(&stubRBACManager{}).RoleUsage)
	req := httptest.NewRequest(http.MethodGet, "/admin/rbac/usage", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
}
