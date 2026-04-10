package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	if !strings.Contains(body, `href="/.well-known/openid-configuration"`) {
		t.Fatalf("body should contain discovery link, got: %s", body)
	}
	if !strings.Contains(body, `href="/oauth2/jwks"`) {
		t.Fatalf("body should contain jwks link, got: %s", body)
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
