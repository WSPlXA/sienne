package handler

import (
	"errors"
	"net/http"

	appclient "idp-server/internal/application/client"
	"idp-server/internal/interfaces/http/dto"

	"github.com/gin-gonic/gin"
)

type ClientRedirectURIHandler struct {
	service appclient.Registrar
}

func NewClientRedirectURIHandler(service appclient.Registrar) *ClientRedirectURIHandler {
	return &ClientRedirectURIHandler{service: service}
}

func (h *ClientRedirectURIHandler) Handle(c *gin.Context) {
	var req dto.RegisterClientRedirectURIRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid redirect uri request"})
		return
	}

	redirectURIs := append([]string(nil), req.RedirectURIs...)
	if req.RedirectURI != "" {
		redirectURIs = append(redirectURIs, req.RedirectURI)
	}

	result, err := h.service.RegisterRedirectURIs(c.Request.Context(), appclient.RegisterRedirectURIsInput{
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
		"client_id":        result.ClientID,
		"client_name":      result.ClientName,
		"redirect_uris":    result.RedirectURIs,
		"registered_count": result.RegisteredCount,
		"skipped_count":    result.SkippedCount,
	})
}
