package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"idp-server/internal/application/register"

	"github.com/gin-gonic/gin"
)

type stubRegistrar struct {
	result *register.RegisterResult
	err    error
	input  register.RegisterInput
}

func (s *stubRegistrar) Register(_ context.Context, input register.RegisterInput) (*register.RegisterResult, error) {
	s.input = input
	return s.result, s.err
}

func TestRegisterHandlerHandleGetIncludesCSRFToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/register", NewRegisterHandler(&stubRegistrar{}).Handle)

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if token, _ := body["csrf_token"].(string); token == "" {
		t.Fatalf("csrf_token = %#v, want non-empty", body["csrf_token"])
	}
	if cookie := findCookie(recorder.Result().Cookies(), csrfCookieName); cookie == nil || cookie.Value == "" {
		t.Fatalf("csrf cookie was not issued")
	}
}

func TestRegisterHandlerHandlePostRejectsMissingCSRFToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubRegistrar{}
	router := gin.New()
	router.POST("/register", NewRegisterHandler(service).Handle)

	body := []byte(`{"username":"alice","email":"alice@example.com","display_name":"Alice","password":"alice1234"}`)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if service.input.Username != "" {
		t.Fatalf("register should not have been called: %#v", service.input)
	}
}

func TestRegisterHandlerHandlePostSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubRegistrar{
		result: &register.RegisterResult{
			UserID:        1,
			UserUUID:      "user-123",
			Username:      "alice",
			Email:         "alice@example.com",
			EmailVerified: false,
			DisplayName:   "Alice",
			Status:        "active",
			CreatedAt:     time.Now().UTC(),
		},
	}
	router := gin.New()
	router.POST("/register", NewRegisterHandler(service).Handle)
	csrfCookie, csrfToken := mustNewCSRFCookie(t)

	body := []byte(`{"username":"alice","email":"alice@example.com","display_name":"Alice","password":"alice1234","csrf_token":"` + csrfToken + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(csrfCookie)
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if service.input.Username != "alice" {
		t.Fatalf("username = %q, want alice", service.input.Username)
	}
}
