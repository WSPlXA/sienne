package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	apppasskey "idp-server/internal/application/passkey"

	"github.com/gin-gonic/gin"
)

type stubPasskeySetupManager struct {
	beginResult *apppasskey.BeginSetupResult
	beginErr    error

	finishResult     *apppasskey.FinishSetupResult
	finishErr        error
	lastSessionID    string
	lastSetupID      string
	lastResponseJSON string
}

func (s *stubPasskeySetupManager) BeginSetup(_ context.Context, sessionID string) (*apppasskey.BeginSetupResult, error) {
	s.lastSessionID = sessionID
	return s.beginResult, s.beginErr
}

func (s *stubPasskeySetupManager) FinishSetup(_ context.Context, sessionID, setupID string, responseJSON []byte) (*apppasskey.FinishSetupResult, error) {
	s.lastSessionID = sessionID
	s.lastSetupID = setupID
	s.lastResponseJSON = string(responseJSON)
	return s.finishResult, s.finishErr
}

func TestPasskeySetupHandlerGetRendersHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/mfa/passkey/setup", NewPasskeySetupHandler(&stubPasskeySetupManager{}).Handle)

	req := httptest.NewRequest(http.MethodGet, "/mfa/passkey/setup?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Ddemo", nil)
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
	if !strings.Contains(body, "<title>Passkey Setup</title>") {
		t.Fatalf("body should contain passkey setup title: %s", body)
	}
}

func TestPasskeySetupHandlerPostBeginReturnsOptions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubPasskeySetupManager{
		beginResult: &apppasskey.BeginSetupResult{
			SetupID:     "setup-1",
			OptionsJSON: []byte(`{"challenge":"dGVzdA","user":{"id":"dXNlcg","name":"alice","displayName":"Alice"}}`),
			ExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
		},
	}
	router := gin.New()
	router.POST("/mfa/passkey/setup", NewPasskeySetupHandler(service).Handle)

	form := url.Values{}
	form.Set("action", "begin")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/mfa/passkey/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-abc"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if service.lastSessionID != "session-abc" {
		t.Fatalf("session id = %q, want session-abc", service.lastSessionID)
	}
	if !strings.Contains(recorder.Body.String(), `"setup_id":"setup-1"`) {
		t.Fatalf("response should contain setup_id, got: %s", recorder.Body.String())
	}
}

func TestPasskeySetupHandlerPostFinishReturnsRedirect(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubPasskeySetupManager{
		finishResult: &apppasskey.FinishSetupResult{
			CredentialID: "credential-1",
		},
	}
	router := gin.New()
	router.POST("/mfa/passkey/setup", NewPasskeySetupHandler(service).Handle)

	form := url.Values{}
	form.Set("action", "finish")
	form.Set("setup_id", "setup-1")
	form.Set("response_json", `{"id":"cred-1"}`)
	form.Set("return_to", "/oauth2/authorize?client_id=demo")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/mfa/passkey/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-abc"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if service.lastSetupID != "setup-1" {
		t.Fatalf("setup id = %q, want setup-1", service.lastSetupID)
	}
	if service.lastResponseJSON != `{"id":"cred-1"}` {
		t.Fatalf("response_json = %q", service.lastResponseJSON)
	}
	if !strings.Contains(recorder.Body.String(), `"redirect_uri":"/oauth2/authorize?client_id=demo"`) {
		t.Fatalf("response should contain redirect_uri, got: %s", recorder.Body.String())
	}
}
