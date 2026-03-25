package handler

import (
	"net/http"

	appclientauth "idp-server/internal/application/clientauth"
	"idp-server/internal/application/oidc"
	"idp-server/internal/interfaces/http/dto"
	pluginport "idp-server/internal/ports/plugin"
	pkgoauth2 "idp-server/pkg/oauth2"

	"github.com/gin-gonic/gin"
)

type IntrospectionHandler struct {
	clientAuthenticator appclientauth.Authenticator
	service             oidc.IntrospectionProvider
}

func NewIntrospectionHandler(clientAuthenticator appclientauth.Authenticator, service oidc.IntrospectionProvider) *IntrospectionHandler {
	return &IntrospectionHandler{
		clientAuthenticator: clientAuthenticator,
		service:             service,
	}
}

func (h *IntrospectionHandler) Handle(c *gin.Context) {
	var req dto.IntrospectRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "invalid_request",
			Description: "invalid introspection request",
		})
		return
	}
	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
		return
	}
	if h.clientAuthenticator == nil || h.service == nil {
		c.JSON(http.StatusInternalServerError, pkgoauth2.Error{
			Code:        "server_error",
			Description: "introspection handler is not configured",
		})
		return
	}

	authResult, err := h.clientAuthenticator.Authenticate(c.Request.Context(), appclientauth.AuthenticateInput{
		AuthorizationHeader: c.GetHeader("Authorization"),
		ClientID:            req.ClientID,
		ClientSecret:        req.ClientSecret,
	})
	if err != nil || authResult == nil || authResult.Method == pluginport.ClientAuthMethodNone {
		description := "client authentication is required"
		if err != nil {
			description = err.Error()
		}
		c.JSON(http.StatusUnauthorized, pkgoauth2.Error{
			Code:        "invalid_client",
			Description: description,
		})
		return
	}

	result, err := h.service.Introspect(c.Request.Context(), oidc.IntrospectionInput{
		AccessToken: req.Token,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, pkgoauth2.Error{
			Code:        "server_error",
			Description: "token introspection failed",
		})
		return
	}

	c.JSON(http.StatusOK, result)
}
