package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appclientauth "idp-server/internal/application/clientauth"
	"idp-server/internal/application/oidc"
	pluginport "idp-server/internal/ports/plugin"

	"github.com/gin-gonic/gin"
)

type stubClientAuthenticator struct {
	result *appclientauth.AuthenticateResult
	err    error
	input  appclientauth.AuthenticateInput
}

func (s *stubClientAuthenticator) Authenticate(_ context.Context, input appclientauth.AuthenticateInput) (*appclientauth.AuthenticateResult, error) {
	s.input = input
	return s.result, s.err
}

type stubIntrospectionProvider struct {
	result *oidc.IntrospectionOutput
	err    error
	input  oidc.IntrospectionInput
}

func (s *stubIntrospectionProvider) Introspect(_ context.Context, input oidc.IntrospectionInput) (*oidc.IntrospectionOutput, error) {
	s.input = input
	return s.result, s.err
}

func TestIntrospectionHandlerHandle(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authenticator := &stubClientAuthenticator{
		result: &appclientauth.AuthenticateResult{
			ClientID: "resource-server",
			Method:   pluginport.ClientAuthMethodClientSecretBasic,
		},
	}
	provider := &stubIntrospectionProvider{
		result: &oidc.IntrospectionOutput{
			Active:   true,
			ClientID: "web-client",
		},
	}

	router := gin.New()
	router.POST("/oauth2/introspect", NewIntrospectionHandler(authenticator, provider).Handle)

	body, err := json.Marshal(map[string]any{
		"token":         "access-token",
		"client_id":     "resource-server",
		"client_secret": "resource-secret",
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", recorder.Code)
	}
	if authenticator.input.ClientID != "resource-server" {
		t.Fatalf("client id = %q, want resource-server", authenticator.input.ClientID)
	}
	if provider.input.AccessToken != "access-token" {
		t.Fatalf("token = %q, want access-token", provider.input.AccessToken)
	}
}

func TestIntrospectionHandlerRejectsUnauthenticatedClient(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.POST("/oauth2/introspect", NewIntrospectionHandler(&stubClientAuthenticator{
		result: &appclientauth.AuthenticateResult{
			ClientID: "public-client",
			Method:   pluginport.ClientAuthMethodNone,
		},
	}, &stubIntrospectionProvider{}).Handle)

	body := []byte(`{"token":"access-token","client_id":"public-client"}`)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/introspect", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want 401", recorder.Code)
	}
}
