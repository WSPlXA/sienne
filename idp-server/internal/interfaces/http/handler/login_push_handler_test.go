package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"idp-server/internal/application/authn"

	"github.com/gin-gonic/gin"
)

func TestLoginPushHandlerGetRendersPage(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/mfa/push", NewLoginPushHandler(&stubAuthenticator{}).Handle)

	req := httptest.NewRequest(http.MethodGet, "/mfa/push?challenge_id=challenge-1&match_code=42", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Approve Sign-in") {
		t.Fatalf("body should contain title, got: %s", body)
	}
	if !strings.Contains(body, "challenge-1") {
		t.Fatalf("body should contain challenge id, got: %s", body)
	}
}

func TestLoginPushHandlerPostApprove(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		decideResult: &authn.PollMFAChallengeResult{
			ChallengeID: "challenge-1",
			MFAMode:     authn.MFAModePushTOTPFallback,
			PushStatus:  authn.MFAPushStatusApproved,
			PushCode:    "42",
			ExpiresAt:   time.Now().UTC().Add(2 * time.Minute),
		},
	}
	router := gin.New()
	router.POST("/mfa/push", NewLoginPushHandler(service).Handle)

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("challenge_id", "challenge-1")
	form.Set("match_code", "42")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/mfa/push", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-approver"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), "approved") {
		t.Fatalf("response should contain approved status, got: %s", recorder.Body.String())
	}
}
