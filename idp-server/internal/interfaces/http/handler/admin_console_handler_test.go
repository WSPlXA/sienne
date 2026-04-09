package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sessiondomain "idp-server/internal/domain/session"
	userdomain "idp-server/internal/domain/user"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"

	"github.com/gin-gonic/gin"
)

func TestAdminConsoleHandlerHandleHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(httpmiddleware.ContextAdminUser, &userdomain.Model{
			ID:            7,
			Username:      "alice-admin",
			RoleCode:      "super_admin",
			PrivilegeMask: 0xFFFFFFFF,
		})
		c.Set(httpmiddleware.ContextAdminSession, &sessiondomain.Model{
			ID:        11,
			SessionID: "session-admin",
		})
		c.Next()
	})
	router.GET("/admin", NewAdminConsoleHandler(&stubRBACManager{}, nil).Handle)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("content type = %q, want text/html", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Admin Console") {
		t.Fatalf("body did not contain admin title: %s", body)
	}
	if !strings.Contains(body, "alice-admin") {
		t.Fatalf("body did not contain admin username: %s", body)
	}
}
