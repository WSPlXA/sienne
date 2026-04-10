package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	userdomain "idp-server/internal/domain/user"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	pkgrbac "idp-server/pkg/rbac"

	"github.com/gin-gonic/gin"
)

func TestOAuthWorkbenchRendersQuickExecuteForms(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewPortalHandler()
	router.GET("/admin/workbench/oauth", handler.OAuthWorkbench)

	req := httptest.NewRequest(http.MethodGet, "/admin/workbench/oauth", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `id="oauth-create-client-form"`) {
		t.Fatalf("body should contain create client form, got: %s", body)
	}
	if !strings.Contains(body, `action="/oauth2/clients"`) {
		t.Fatalf("body should contain create client action, got: %s", body)
	}
	if !strings.Contains(body, `id="oauth-register-redirect-form"`) {
		t.Fatalf("body should contain redirect registration form, got: %s", body)
	}
	if !strings.Contains(body, `data-read-endpoint="/.well-known/openid-configuration"`) {
		t.Fatalf("body should contain discovery read button endpoint, got: %s", body)
	}
	if !strings.Contains(body, `data-read-endpoint="/oauth2/jwks"`) {
		t.Fatalf("body should contain jwks read button endpoint, got: %s", body)
	}
	if !strings.Contains(body, `id="oauth-read-result"`) {
		t.Fatalf("body should contain oauth read result panel, got: %s", body)
	}
}

func TestSupportWorkbenchDoesNotRenderOAuthQuickExecuteForms(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewPortalHandler()
	router.GET("/admin/workbench/support", handler.SupportWorkbench)

	req := httptest.NewRequest(http.MethodGet, "/admin/workbench/support", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	body := recorder.Body.String()
	if strings.Contains(body, `id="oauth-create-client-form"`) {
		t.Fatalf("support workbench should not contain oauth create client form, got: %s", body)
	}
}

func TestOAuthWorkbenchHidesRBACLinkForOAuthAdminMask(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewPortalHandler()
	router.GET("/admin/workbench/oauth", func(c *gin.Context) {
		c.Set(httpmiddleware.ContextAdminUser, &userdomain.Model{
			Username:      "bob",
			RoleCode:      pkgrbac.RoleOAuthAdmin,
			PrivilegeMask: pkgrbac.MaskOAuthAdmin,
		})
		handler.OAuthWorkbench(c)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/workbench/oauth", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	body := recorder.Body.String()
	if strings.Contains(body, ">Open RBAC Console<") {
		t.Fatalf("oauth admin workbench should not expose rbac console link, got: %s", body)
	}
}

func TestSupportWorkbenchShowsRBACLinkWhenPermissionMatches(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	handler := NewPortalHandler()
	router.GET("/admin/workbench/support", func(c *gin.Context) {
		c.Set(httpmiddleware.ContextAdminUser, &userdomain.Model{
			Username:      "alice",
			RoleCode:      pkgrbac.RoleSupport,
			PrivilegeMask: pkgrbac.MaskSupport,
		})
		handler.SupportWorkbench(c)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/workbench/support", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, ">Open RBAC Console<") {
		t.Fatalf("support workbench should expose rbac console link when permitted, got: %s", body)
	}
}
