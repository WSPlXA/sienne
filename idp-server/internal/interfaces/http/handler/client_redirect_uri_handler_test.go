package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appclient "idp-server/internal/application/client"

	"github.com/gin-gonic/gin"
)

type stubRedirectURIRegistrar struct {
	result *appclient.RegisterRedirectURIsResult
	err    error
	input  appclient.RegisterRedirectURIsInput
}

func (s *stubRedirectURIRegistrar) RegisterRedirectURIs(_ context.Context, input appclient.RegisterRedirectURIsInput) (*appclient.RegisterRedirectURIsResult, error) {
	s.input = input
	return s.result, s.err
}

func TestClientRedirectURIHandlerHandle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubRedirectURIRegistrar{
		result: &appclient.RegisterRedirectURIsResult{
			ClientID:        "web-client",
			ClientName:      "Web Client",
			RedirectURIs:    []string{"https://app.example.com/callback"},
			RegisteredCount: 1,
			SkippedCount:    0,
		},
	}
	router := gin.New()
	router.POST("/oauth2/clients/:client_id/redirect-uris", NewClientRedirectURIHandler(service).Handle)

	body, err := json.Marshal(map[string]any{
		"redirect_uri": "https://app.example.com/callback",
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth2/clients/web-client/redirect-uris", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if service.input.ClientID != "web-client" {
		t.Fatalf("client id = %q, want web-client", service.input.ClientID)
	}
	if len(service.input.RedirectURIs) != 1 || service.input.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Fatalf("redirect uris = %#v", service.input.RedirectURIs)
	}
}
