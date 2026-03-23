package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"idp-server/internal/application/authn"

	"github.com/gin-gonic/gin"
)

type stubAuthenticator struct {
	result *authn.AuthenticateResult
	err    error
	input  authn.AuthenticateInput
}

func (s *stubAuthenticator) Authenticate(_ context.Context, input authn.AuthenticateInput) (*authn.AuthenticateResult, error) {
	s.input = input
	return s.result, s.err
}

func TestLoginHandlerHandleGetHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/login", NewLoginHandler(&stubAuthenticator{}).Handle)

	req := httptest.NewRequest(http.MethodGet, "/login?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Ddemo", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("content type = %q, want text/html", got)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "<title>Login</title>") {
		t.Fatalf("body did not contain login title: %s", body)
	}
	if !strings.Contains(body, `name="return_to" value="/oauth2/authorize?client_id=demo"`) {
		t.Fatalf("body did not preserve return_to: %s", body)
	}
}

func TestLoginHandlerHandlePostSuccessRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		result: &authn.AuthenticateResult{
			SessionID: "session-123",
			UserID:    1,
			Subject:   "user-123",
			ExpiresAt: time.Now().Add(30 * time.Minute),
		},
	}
	router := gin.New()
	router.POST("/login", NewLoginHandler(service).Handle)

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "alice123")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/oauth2/authorize?client_id=demo" {
		t.Fatalf("location = %q, want /oauth2/authorize?client_id=demo", got)
	}
	if got := recorder.Header().Get("Set-Cookie"); !strings.Contains(got, "idp_session=session-123") {
		t.Fatalf("set-cookie = %q, want idp_session=session-123", got)
	}
	if service.input.Username != "alice" {
		t.Fatalf("username = %q, want alice", service.input.Username)
	}
}

func TestLoginHandlerHandlePostErrorRendersHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.POST("/login", NewLoginHandler(&stubAuthenticator{err: authn.ErrInvalidCredentials}).Handle)

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "wrong-password")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("content type = %q, want text/html", got)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "invalid credentials") {
		t.Fatalf("body did not contain error message: %s", body)
	}
	if !strings.Contains(body, `value="alice"`) {
		t.Fatalf("body did not preserve username: %s", body)
	}
}
