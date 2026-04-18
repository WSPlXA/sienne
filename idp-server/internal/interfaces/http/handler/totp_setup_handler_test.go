package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	appmfa "idp-server/internal/application/mfa"

	"github.com/gin-gonic/gin"
)

type stubMFASetupManager struct {
	beginResult *appmfa.SetupResult
	beginErr    error

	confirmResult   *appmfa.ConfirmResult
	confirmErr      error
	confirmSession  string
	confirmCode     string
	confirmReturnTo string

	challengeResult   *appmfa.ConfirmResult
	challengeErr      error
	challengeSession  string
	challengeReturnTo string
}

func (s *stubMFASetupManager) BeginSetup(_ context.Context, _ string) (*appmfa.SetupResult, error) {
	return s.beginResult, s.beginErr
}

func (s *stubMFASetupManager) ConfirmSetup(_ context.Context, sessionID string, code string, returnTo string) (*appmfa.ConfirmResult, error) {
	s.confirmSession = sessionID
	s.confirmCode = code
	s.confirmReturnTo = returnTo
	return s.confirmResult, s.confirmErr
}

func (s *stubMFASetupManager) BeginLoginChallenge(_ context.Context, sessionID string, returnTo string) (*appmfa.ConfirmResult, error) {
	s.challengeSession = sessionID
	s.challengeReturnTo = returnTo
	return s.challengeResult, s.challengeErr
}

func TestTOTPSetupHandlerGetAlreadyEnabledStartsLoginTOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubMFASetupManager{
		beginResult: &appmfa.SetupResult{
			AlreadyEnabled: true,
		},
		challengeResult: &appmfa.ConfirmResult{
			Enabled:        true,
			TOTPRequired:   true,
			MFAChallengeID: "challenge-existing",
		},
	}
	router := gin.New()
	router.GET("/mfa/totp/setup", NewTOTPSetupHandler(service).Handle)

	req := httptest.NewRequest(http.MethodGet, "/mfa/totp/setup?return_to=%2Fadmin", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-low-acr"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/login/totp" {
		t.Fatalf("location = %q, want /login/totp", got)
	}
	if service.challengeSession != "session-low-acr" {
		t.Fatalf("challenge session = %q, want session-low-acr", service.challengeSession)
	}
	if service.challengeReturnTo != "/admin" {
		t.Fatalf("challenge return_to = %q, want /admin", service.challengeReturnTo)
	}
	if cookie := findCookie(recorder.Result().Cookies(), mfaChallengeCookieName); cookie == nil || cookie.Value != "challenge-existing" {
		t.Fatalf("mfa challenge cookie = %#v, want challenge-existing", cookie)
	}
	if cookie := findCookie(recorder.Result().Cookies(), "idp_session"); cookie == nil || cookie.Value != "" {
		t.Fatalf("idp_session cookie = %#v, want cleared cookie", cookie)
	}
}

func TestTOTPSetupHandlerPostSuccessRedirectsToLoginTOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubMFASetupManager{
		confirmResult: &appmfa.ConfirmResult{
			Enabled:        true,
			TOTPRequired:   true,
			MFAChallengeID: "challenge-123",
		},
	}
	router := gin.New()
	router.POST("/mfa/totp/setup", NewTOTPSetupHandler(service).Handle)

	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form := url.Values{}
	form.Set("code", "123456")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	req.AddCookie(csrfCookie)
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-abc"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/login/totp" {
		t.Fatalf("location = %q, want /login/totp", got)
	}
	if service.confirmSession != "session-abc" {
		t.Fatalf("confirm session = %q, want session-abc", service.confirmSession)
	}
	if service.confirmCode != "123456" {
		t.Fatalf("confirm code = %q, want 123456", service.confirmCode)
	}
	if service.confirmReturnTo != "/oauth2/authorize?client_id=demo" {
		t.Fatalf("confirm return_to = %q", service.confirmReturnTo)
	}
	if cookie := findCookie(recorder.Result().Cookies(), mfaChallengeCookieName); cookie == nil || cookie.Value != "challenge-123" {
		t.Fatalf("mfa challenge cookie = %#v, want challenge-123", cookie)
	}
	if cookie := findCookie(recorder.Result().Cookies(), "idp_session"); cookie == nil || cookie.Value != "" {
		t.Fatalf("idp_session cookie = %#v, want cleared cookie", cookie)
	}
}

func TestTOTPSetupHandlerPostSuccessReturnsJSONChallenge(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubMFASetupManager{
		confirmResult: &appmfa.ConfirmResult{
			Enabled:        true,
			TOTPRequired:   true,
			MFAChallengeID: "challenge-xyz",
		},
	}
	router := gin.New()
	router.POST("/mfa/totp/setup", NewTOTPSetupHandler(service).Handle)

	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form := url.Values{}
	form.Set("code", "123456")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.AddCookie(csrfCookie)
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-abc"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body error = %v", err)
	}
	if got, _ := body["redirect_uri"].(string); got != "/login/totp" {
		t.Fatalf("redirect_uri = %q, want /login/totp", got)
	}
	if got, _ := body["challenge_id"].(string); got != "challenge-xyz" {
		t.Fatalf("challenge_id = %q, want challenge-xyz", got)
	}
	if got, _ := body["mfa_required"].(bool); !got {
		t.Fatalf("mfa_required = %#v, want true", body["mfa_required"])
	}
}
