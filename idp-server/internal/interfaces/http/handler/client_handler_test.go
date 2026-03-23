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

type stubClientCreator struct {
	result *appclient.CreateClientResult
	err    error
	input  appclient.CreateClientInput
}

func (s *stubClientCreator) CreateClient(_ context.Context, input appclient.CreateClientInput) (*appclient.CreateClientResult, error) {
	s.input = input
	return s.result, s.err
}

func TestClientHandlerCreate(t *testing.T) {
	gin.SetMode(gin.TestMode)

	service := &stubClientCreator{
		result: &appclient.CreateClientResult{
			ClientID:                "demo-web-client",
			ClientName:              "Demo Web Client",
			ClientType:              "confidential",
			TokenEndpointAuthMethod: "client_secret_basic",
			RequirePKCE:             true,
			RequireConsent:          true,
			AccessTokenTTLSeconds:   3600,
			RefreshTokenTTLSeconds:  2592000,
			IDTokenTTLSeconds:       3600,
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			AuthMethods:             []string{"client_secret_basic"},
			Scopes:                  []string{"openid", "profile"},
			RedirectURIs:            []string{"https://app.example.com/callback"},
			Status:                  "active",
		},
	}
	router := gin.New()
	router.POST("/oauth2/clients", NewClientHandler(service).Create)

	body, err := json.Marshal(map[string]any{
		"client_id":      "demo-web-client",
		"client_name":    "Demo Web Client",
		"client_secret":  "super-secret-1",
		"grant_types":    []string{"authorization_code", "refresh_token"},
		"scopes":         []string{"openid", "profile"},
		"redirect_uris":  []string{"https://app.example.com/callback"},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth2/clients", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if service.input.ClientID != "demo-web-client" {
		t.Fatalf("client id = %q, want demo-web-client", service.input.ClientID)
	}
	if len(service.input.RedirectURIs) != 1 || service.input.RedirectURIs[0] != "https://app.example.com/callback" {
		t.Fatalf("redirect uris = %#v", service.input.RedirectURIs)
	}
}
