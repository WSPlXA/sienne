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

func TestLoginTOTPStatusFinalizesApprovedPush(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		pollResult: &authn.PollMFAChallengeResult{
			ChallengeID: "challenge-1",
			MFAMode:     authn.MFAModePushTOTPFallback,
			PushStatus:  authn.MFAPushStatusApproved,
			PushCode:    "42",
			ExpiresAt:   time.Now().UTC().Add(2 * time.Minute),
		},
		finalizeResult: &authn.AuthenticateResult{
			SessionID: "session-1",
			UserID:    7,
			Subject:   "user-7",
			ReturnTo:  "/oauth2/authorize?client_id=web-client",
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
		},
	}

	router := gin.New()
	router.GET("/login/totp", NewLoginTOTPHandler(service).Handle)

	req := httptest.NewRequest(http.MethodGet, "/login/totp?mode=status", nil)
	req.AddCookie(&http.Cookie{Name: mfaChallengeCookieName, Value: "challenge-1"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if cookie := findCookie(recorder.Result().Cookies(), "idp_session"); cookie == nil || cookie.Value != "session-1" {
		t.Fatalf("idp_session cookie = %#v, want session-1", cookie)
	}
	if !strings.Contains(recorder.Body.String(), `"authenticated":true`) {
		t.Fatalf("response body should indicate authenticated=true: %s", recorder.Body.String())
	}
}

func TestLoginTOTPPushDecisionRejectsApproverMismatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		decideErr: authn.ErrMFAApproverMismatch,
	}
	router := gin.New()
	router.POST("/login/totp", NewLoginTOTPHandler(service).Handle)

	form := url.Values{}
	form.Set("action", "approve")
	form.Set("challenge_id", "challenge-1")
	form.Set("match_code", "42")
	req := httptest.NewRequest(http.MethodPost, "/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestLoginTOTPGetRendersPushChallenge(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		pollResult: &authn.PollMFAChallengeResult{
			ChallengeID: "challenge-1",
			MFAMode:     authn.MFAModePushTOTPFallback,
			PushStatus:  authn.MFAPushStatusPending,
			PushCode:    "58",
			ExpiresAt:   time.Now().UTC().Add(2 * time.Minute),
		},
	}
	router := gin.New()
	router.GET("/login/totp", NewLoginTOTPHandler(service).Handle)

	req := httptest.NewRequest(http.MethodGet, "/login/totp", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: mfaChallengeCookieName, Value: "challenge-1"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "Push Challenge") {
		t.Fatalf("body should contain push section: %s", body)
	}
	if !strings.Contains(body, "58") {
		t.Fatalf("body should contain push code: %s", body)
	}
}

func TestLoginTOTPPasskeyBeginReturnsOptions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		beginPasskeyResult: &authn.BeginMFAPasskeyResult{
			ChallengeID: "challenge-1",
			OptionsJSON: []byte(`{"challenge":"dGVzdA","allowCredentials":[]}`),
			ExpiresAt:   time.Now().UTC().Add(2 * time.Minute),
		},
	}
	router := gin.New()
	router.POST("/login/totp", NewLoginTOTPHandler(service).Handle)

	form := url.Values{}
	form.Set("action", "passkey_begin")
	form.Set("challenge_id", "challenge-1")
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(&http.Cookie{Name: mfaChallengeCookieName, Value: "challenge-1"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if !strings.Contains(recorder.Body.String(), `"challenge_id":"challenge-1"`) {
		t.Fatalf("response should contain challenge id, got: %s", recorder.Body.String())
	}
}

func TestLoginTOTPPasskeyFinishSetsSessionCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubAuthenticator{
		verifyPasskeyResult: &authn.AuthenticateResult{
			SessionID: "session-passkey-1",
			UserID:    11,
			Subject:   "user-11",
			ReturnTo:  "/oauth2/authorize?client_id=web-client",
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute),
		},
	}
	router := gin.New()
	router.POST("/login/totp", NewLoginTOTPHandler(service).Handle)

	form := url.Values{}
	form.Set("action", "passkey_finish")
	form.Set("challenge_id", "challenge-1")
	form.Set("response_json", `{"id":"cred-1"}`)
	csrfCookie, csrfToken := mustNewCSRFCookie(t)
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	req.AddCookie(&http.Cookie{Name: mfaChallengeCookieName, Value: "challenge-1"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	if cookie := findCookie(recorder.Result().Cookies(), "idp_session"); cookie == nil || cookie.Value != "session-passkey-1" {
		t.Fatalf("idp_session cookie = %#v, want session-passkey-1", cookie)
	}
	if !strings.Contains(recorder.Body.String(), `"authenticated":true`) {
		t.Fatalf("response should indicate authenticated=true: %s", recorder.Body.String())
	}
}
