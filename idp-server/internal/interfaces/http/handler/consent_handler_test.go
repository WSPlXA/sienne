package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	appconsent "idp-server/internal/application/consent"

	"github.com/gin-gonic/gin"
)

type stubConsentManager struct {
	prepareResult *appconsent.PrepareResult
	prepareErr    error
	prepareInput  appconsent.PrepareInput
	decideResult  *appconsent.DecideResult
	decideErr     error
	decideInput   appconsent.DecideInput
}

func (s *stubConsentManager) Prepare(_ context.Context, input appconsent.PrepareInput) (*appconsent.PrepareResult, error) {
	s.prepareInput = input
	return s.prepareResult, s.prepareErr
}

func (s *stubConsentManager) Decide(_ context.Context, input appconsent.DecideInput) (*appconsent.DecideResult, error) {
	s.decideInput = input
	return s.decideResult, s.decideErr
}

func TestConsentHandlerHandleGetHTMLIncludesCSRFToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubConsentManager{
		prepareResult: &appconsent.PrepareResult{
			ClientID:   "demo",
			ClientName: "Demo App",
			Scopes:     []string{"openid", "profile"},
			ReturnTo:   "/oauth2/authorize?client_id=demo",
		},
	}
	router := gin.New()
	router.GET("/consent", NewConsentHandler(service).Handle)

	req := httptest.NewRequest(http.MethodGet, "/consent?return_to=%2Foauth2%2Fauthorize%3Fclient_id%3Ddemo", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-123"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `name="csrf_token" value="`) {
		t.Fatalf("body did not contain csrf token field: %s", body)
	}
	if cookie := findCookie(recorder.Result().Cookies(), csrfCookieName); cookie == nil || cookie.Value == "" {
		t.Fatalf("csrf cookie was not issued")
	}
}

func TestConsentHandlerHandlePostSuccessRedirects(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubConsentManager{
		decideResult: &appconsent.DecideResult{
			RedirectURI: "/oauth2/authorize?client_id=demo&code=code-123",
		},
	}
	router := gin.New()
	router.POST("/consent", NewConsentHandler(service).Handle)
	csrfCookie, csrfToken := mustNewCSRFCookie(t)

	form := url.Values{}
	form.Set("action", "accept")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")
	form.Set("csrf_token", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-123"})
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/oauth2/authorize?client_id=demo&code=code-123" {
		t.Fatalf("location = %q", got)
	}
	if service.decideInput.Action != "accept" {
		t.Fatalf("action = %q, want accept", service.decideInput.Action)
	}
}

func TestConsentHandlerHandlePostRejectsMissingCSRFToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubConsentManager{}
	router := gin.New()
	router.POST("/consent", NewConsentHandler(service).Handle)

	form := url.Values{}
	form.Set("action", "accept")
	form.Set("return_to", "/oauth2/authorize?client_id=demo")

	req := httptest.NewRequest(http.MethodPost, "/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-123"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if service.decideInput.Action != "" {
		t.Fatalf("decide should not have been called: %#v", service.decideInput)
	}
}
