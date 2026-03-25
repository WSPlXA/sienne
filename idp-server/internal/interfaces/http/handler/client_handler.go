package handler

import (
	"errors"
	"net/http"

	appclient "idp-server/internal/application/client"
	"idp-server/internal/interfaces/http/dto"

	"github.com/gin-gonic/gin"
)

type ClientHandler struct {
	service appclient.Creator
}

func NewClientHandler(service appclient.Creator) *ClientHandler {
	return &ClientHandler{service: service}
}

func (h *ClientHandler) Create(c *gin.Context) {
	var req dto.CreateClientRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid client request"})
		return
	}

	result, err := h.service.CreateClient(c.Request.Context(), appclient.CreateClientInput{
		ClientID:                req.ClientID,
		ClientName:              req.ClientName,
		ClientSecret:            req.ClientSecret,
		ClientType:              req.ClientType,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		RequirePKCE:             req.RequirePKCE,
		RequireConsent:          req.RequireConsent,
		AccessTokenTTLSeconds:   req.AccessTokenTTLSeconds,
		RefreshTokenTTLSeconds:  req.RefreshTokenTTLSeconds,
		IDTokenTTLSeconds:       req.IDTokenTTLSeconds,
		GrantTypes:              req.GrantTypes,
		Scopes:                  req.Scopes,
		RedirectURIs:            req.RedirectURIs,
		PostLogoutRedirectURIs:  req.PostLogoutRedirectURIs,
		Status:                  req.Status,
	})
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, appclient.ErrClientIDAlreadyExists):
			status = http.StatusConflict
		case errors.Is(err, appclient.ErrInvalidClientID),
			errors.Is(err, appclient.ErrInvalidClientName),
			errors.Is(err, appclient.ErrInvalidClientType),
			errors.Is(err, appclient.ErrInvalidClientSecret),
			errors.Is(err, appclient.ErrInvalidAuthMethod),
			errors.Is(err, appclient.ErrInvalidGrantType),
			errors.Is(err, appclient.ErrInvalidScope),
			errors.Is(err, appclient.ErrRedirectURIRequired),
			errors.Is(err, appclient.ErrInvalidRedirectURI),
			errors.Is(err, appclient.ErrInvalidClientConfig):
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}

		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"client_id":                  result.ClientID,
		"client_name":                result.ClientName,
		"client_type":                result.ClientType,
		"token_endpoint_auth_method": result.TokenEndpointAuthMethod,
		"require_pkce":               result.RequirePKCE,
		"require_consent":            result.RequireConsent,
		"access_token_ttl_seconds":   result.AccessTokenTTLSeconds,
		"refresh_token_ttl_seconds":  result.RefreshTokenTTLSeconds,
		"id_token_ttl_seconds":       result.IDTokenTTLSeconds,
		"grant_types":                result.GrantTypes,
		"auth_methods":               result.AuthMethods,
		"scopes":                     result.Scopes,
		"redirect_uris":              result.RedirectURIs,
		"post_logout_redirect_uris":  result.PostLogoutRedirectURIs,
		"status":                     result.Status,
	})
}
