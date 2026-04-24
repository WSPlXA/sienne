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
	result              *authn.AuthenticateResult
	err                 error
	input               authn.AuthenticateInput
	beginPasskeyResult  *authn.BeginMFAPasskeyResult
	beginPasskeyErr     error
	verifyPasskeyResult *authn.AuthenticateResult
	verifyPasskeyErr    error
	pollResult          *authn.PollMFAChallengeResult
	pollErr             error
	decideResult        *authn.PollMFAChallengeResult
	decideErr           error
	finalizeResult      *authn.AuthenticateResult
	finalizeErr         error
}

func (s *stubAuthenticator) Authenticate(_ context.Context, input authn.AuthenticateInput) (*authn.AuthenticateResult, error) {
	s.input = input
	return s.result, s.err
}

func (s *stubAuthenticator) VerifyTOTP(_ context.Context, _ authn.VerifyTOTPInput) (*authn.AuthenticateResult, error) {
	return s.result, s.err
}

func (s *stubAuthenticator) BeginMFAPasskey(_ context.Context, _ authn.BeginMFAPasskeyInput) (*authn.BeginMFAPasskeyResult, error) {
	return s.beginPasskeyResult, s.beginPasskeyErr
}

func (s *stubAuthenticator) VerifyMFAPasskey(_ context.Context, _ authn.VerifyMFAPasskeyInput) (*authn.AuthenticateResult, error) {
	if s.verifyPasskeyResult != nil || s.verifyPasskeyErr != nil {
		return s.verifyPasskeyResult, s.verifyPasskeyErr
	}
	return s.result, s.err
}

func (s *stubAuthenticator) PollMFAChallenge(_ context.Context, _ authn.PollMFAChallengeInput) (*authn.PollMFAChallengeResult, error) {
	return s.pollResult, s.pollErr
}

func (s *stubAuthenticator) DecideMFAPush(_ context.Context, _ authn.DecideMFAPushInput) (*authn.PollMFAChallengeResult, error) {
	return s.decideResult, s.decideErr
}

func (s *stubAuthenticator) FinalizeMFAPush(_ context.Context, _ authn.FinalizeMFAPushInput) (*authn.AuthenticateResult, error) {
	if s.finalizeResult != nil || s.finalizeErr != nil {
		return s.finalizeResult, s.finalizeErr
	}
	return s.result, s.err
}

func TestLoginHandlerHandleGetHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/login", NewLoginHandler(&stubAuthenticator{}, false).Handle)

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
	if !strings.Contains(body, "<title>Sign In</title>") {
		t.Fatalf("body did not contain login title: %s", body)
	}
	if !strings.Contains(body, `name="return_to" value="/oauth2/authorize?client_id=demo"`) {
		t.Fatalf("body did not preserve return_to: %s", body)
	}
	if !strings.Contains(body, `name="csrf_token" value="`) {
		t.Fatalf("body did not contain csrf token field: %s", body)
	}
	if cookie := findCookie(recorder.Result().Cookies(), csrfCookieName); cookie == nil || cookie.Value == "" {
		t.Fatalf("csrf cookie was not issued")
	} else if !cookie.Secure {
		t.Fatalf("csrf cookie Secure = %v, want true", cookie.Secure)
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
	router.POST("/login", NewLoginHandler(service, false).Handle)

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "alice123")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/oauth2/authorize?client_id=demo" {
		t.Fatalf("location = %q, want /oauth2/authorize?client_id=demo", got)
	}
	if cookie := findCookie(recorder.Result().Cookies(), "idp_session"); cookie == nil || cookie.Value != "session-123" {
		t.Fatalf("idp_session cookie = %#v, want session-123", cookie)
	} else if !cookie.Secure {
		t.Fatalf("idp_session cookie Secure = %v, want true", cookie.Secure)
	}
	if service.input.Username != "alice" {
		t.Fatalf("username = %q, want alice", service.input.Username)
	}
}

func TestLoginHandlerHandlePostRedirectsByRoleWhenReturnToMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		result: &authn.AuthenticateResult{
			SessionID: "session-777",
			UserID:    7,
			Subject:   "user-777",
			RoleCode:  "support",
			ExpiresAt: time.Now().Add(30 * time.Minute),
		},
	}
	router := gin.New()
	router.POST("/login", NewLoginHandler(service, false).Handle)

	form := url.Values{}
	form.Set("username", "bob")
	form.Set("password", "bob123")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/admin/workbench/support" {
		t.Fatalf("location = %q, want /admin/workbench/support", got)
	}
}

func TestLoginHandlerHandlePostSuccessWritesAuditEvent(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		result: &authn.AuthenticateResult{
			SessionID: "session-audit-1",
			UserID:    12,
			Subject:   "user-12",
			RoleCode:  "support",
			ExpiresAt: time.Now().Add(30 * time.Minute),
		},
	}
	auditRepo := &stubAuditEventRepository{}
	router := gin.New()
	router.POST("/login", NewLoginHandler(service, false, auditRepo).Handle)

	form := url.Values{}
	form.Set("username", "bob")
	form.Set("password", "bob123")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if len(auditRepo.events) != 1 {
		t.Fatalf("audit event count = %d, want 1", len(auditRepo.events))
	}
	if auditRepo.events[0].EventType != "auth.login.succeeded" {
		t.Fatalf("audit event type = %q, want auth.login.succeeded", auditRepo.events[0].EventType)
	}
}

func TestLoginHandlerHandlePostRedirectsToMFASetupWhenEnrollmentRequired(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		result: &authn.AuthenticateResult{
			SessionID:             "session-enroll-1",
			UserID:                1,
			Subject:               "user-123",
			MFAEnrollmentRequired: true,
			ExpiresAt:             time.Now().Add(30 * time.Minute),
		},
		err: authn.ErrMFAEnrollmentRequired,
	}
	router := gin.New()
	router.POST("/login", NewLoginHandler(service, false).Handle)

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "alice123")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/mfa/passkey/setup?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Ddemo" {
		t.Fatalf("location = %q, want mfa setup with return_to", got)
	}
	if cookie := findCookie(recorder.Result().Cookies(), "idp_session"); cookie == nil || cookie.Value != "session-enroll-1" {
		t.Fatalf("idp_session cookie = %#v, want session-enroll-1", cookie)
	}
}

func TestLoginHandlerHandlePostRejectsMissingCSRFToken(t *testing.T) {
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
	router.POST("/login", NewLoginHandler(service, false).Handle)

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "alice123")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if service.input.Username != "" {
		t.Fatalf("authenticate should not have been called: %#v", service.input)
	}
}

func TestLoginHandlerHandlePostRejectsExternalReturnTo(t *testing.T) {
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
	router.POST("/login", NewLoginHandler(service, false).Handle)

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "alice123")
	form.Set("return_to", "https://evil.example/phish")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if got := recorder.Header().Get("Location"); got != "" {
		t.Fatalf("location = %q, want empty", got)
	}
	if service.input.ReturnTo != "" {
		t.Fatalf("return_to = %q, want empty", service.input.ReturnTo)
	}
}

func TestLoginHandlerHandlePostErrorRendersHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.POST("/login", NewLoginHandler(&stubAuthenticator{err: authn.ErrInvalidCredentials}, false).Handle)

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "wrong-password")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("content type = %q, want text/html", got)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Invalid username or password.") {
		t.Fatalf("body did not contain error message: %s", body)
	}
	if !strings.Contains(body, `value="alice"`) {
		t.Fatalf("body did not preserve username: %s", body)
	}
}

func TestLoginHandlerHandleGetFederatedRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.POST("/login", NewLoginHandler(&stubAuthenticator{
		result: &authn.AuthenticateResult{
			RedirectURI: "https://issuer.example.com/authorize?state=demo",
		},
	}, true).Handle)

	form := url.Values{}
	form.Set("method", "federated_oidc")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "https://issuer.example.com/authorize?state=demo" {
		t.Fatalf("location = %q", got)
	}
}

func TestLoginHandlerHandleGetFederatedCallbackSetsSessionAndRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/login", NewLoginHandler(&stubAuthenticator{
		result: &authn.AuthenticateResult{
			SessionID:   "session-456",
			UserID:      9,
			Subject:     "subject-9",
			RedirectURI: "/oauth2/authorize?client_id=demo",
			ExpiresAt:   time.Now().Add(30 * time.Minute),
		},
	}, true).Handle)

	req := httptest.NewRequest(http.MethodGet, "/login?code=code-123&state=state-123", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/oauth2/authorize?client_id=demo" {
		t.Fatalf("location = %q", got)
	}
	if cookie := findCookie(recorder.Result().Cookies(), "idp_session"); cookie == nil || cookie.Value != "session-456" {
		t.Fatalf("idp_session cookie = %#v, want session-456", cookie)
	} else if !cookie.Secure {
		t.Fatalf("idp_session cookie Secure = %v, want true", cookie.Secure)
	}
	if cookie := findCookie(recorder.Result().Cookies(), csrfCookieName); cookie == nil || cookie.Value == "" {
		t.Fatalf("csrf cookie was not issued")
	} else if !cookie.Secure {
		t.Fatalf("csrf cookie Secure = %v, want true", cookie.Secure)
	}
}

func TestLoginHandlerHandleGetFederatedCallbackRejectsExternalRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/login", NewLoginHandler(&stubAuthenticator{
		result: &authn.AuthenticateResult{
			SessionID:   "session-456",
			UserID:      9,
			Subject:     "subject-9",
			RedirectURI: "https://evil.example/phish",
			ExpiresAt:   time.Now().Add(30 * time.Minute),
		},
	}, true).Handle)

	req := httptest.NewRequest(http.MethodGet, "/login?code=code-123&state=state-123", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if got := recorder.Header().Get("Location"); got != "" {
		t.Fatalf("location = %q, want empty", got)
	}
}

func TestLoginHandlerHandleGetRejectsExternalReturnTo(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/login", NewLoginHandler(&stubAuthenticator{}, false).Handle)

	req := httptest.NewRequest(http.MethodGet, "/login?return_to=https://evil.example/phish", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestLoginHandlerHandleGetHTMLShowsFederatedOIDCButton(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/login", NewLoginHandler(&stubAuthenticator{}, true).Handle)

	req := httptest.NewRequest(http.MethodGet, "/login?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Ddemo", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	body := recorder.Body.String()
	if !strings.Contains(body, "Sign in with OpenID Connect") {
		t.Fatalf("body did not contain federated oidc button: %s", body)
	}
	if !strings.Contains(body, `name="method" value="federated_oidc"`) {
		t.Fatalf("body did not contain federated login method field: %s", body)
	}
}
