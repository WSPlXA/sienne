package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	appsession "idp-server/internal/application/session"

	"github.com/gin-gonic/gin"
)

type stubSessionManager struct {
	input appsession.LogoutInput
	err   error
}

func (s *stubSessionManager) Logout(_ context.Context, input appsession.LogoutInput) (*appsession.LogoutResult, error) {
	s.input = input
	return &appsession.LogoutResult{SessionID: input.SessionID}, s.err
}

func TestLogoutHandlerHandleJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubSessionManager{}
	router := gin.New()
	router.POST("/logout", NewLogoutHandler(service).Handle)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-123"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if service.input.SessionID != "session-123" {
		t.Fatalf("session id = %q, want session-123", service.input.SessionID)
	}
	if got := recorder.Header().Get("Set-Cookie"); !strings.Contains(got, "idp_session=") {
		t.Fatalf("set-cookie = %q, want cleared idp_session", got)
	}
}

func TestLogoutHandlerHandleRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubSessionManager{}
	router := gin.New()
	router.POST("/logout", NewLogoutHandler(service).Handle)

	form := url.Values{}
	form.Set("return_to", "/login?from=logout")

	req := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-123"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/login?from=logout" {
		t.Fatalf("location = %q, want /login?from=logout", got)
	}
}
