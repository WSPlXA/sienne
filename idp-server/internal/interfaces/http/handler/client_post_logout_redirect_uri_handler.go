package handler

import (
	"errors"
	"net/http"

	appclient "idp-server/internal/application/client"
	"idp-server/internal/interfaces/http/dto"

	"github.com/gin-gonic/gin"
)

type ClientPostLogoutRedirectURIHandler struct {
	service appclient.PostLogoutRegistrar
}

func NewClientPostLogoutRedirectURIHandler(service appclient.PostLogoutRegistrar) *ClientPostLogoutRedirectURIHandler {
	return &ClientPostLogoutRedirectURIHandler{service: service}
}

func (h *ClientPostLogoutRedirectURIHandler) Handle(c *gin.Context) {
	var req dto.RegisterClientRedirectURIRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid post logout redirect uri request"})
		return
	}

	redirectURIs := append([]string(nil), req.RedirectURIs...)
	if req.RedirectURI != "" {
		redirectURIs = append(redirectURIs, req.RedirectURI)
	}

	result, err := h.service.RegisterPostLogoutRedirectURIs(c.Request.Context(), appclient.RegisterPostLogoutRedirectURIsInput{
		ClientID:     c.Param("client_id"),
		RedirectURIs: redirectURIs,
	})
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, appclient.ErrClientNotFound):
			status = http.StatusNotFound
		case errors.Is(err, appclient.ErrInvalidClientID),
			errors.Is(err, appclient.ErrRedirectURIRequired),
			errors.Is(err, appclient.ErrInvalidRedirectURI):
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}

		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"client_id":                 result.ClientID,
		"client_name":               result.ClientName,
		"post_logout_redirect_uris": result.RedirectURIs,
		"registered_count":          result.RegisteredCount,
		"skipped_count":             result.SkippedCount,
	})
}
