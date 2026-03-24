package handler

import (
	"errors"
	"net/http"
	"strings"

	appconsent "idp-server/internal/application/consent"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type ConsentHandler struct {
	service appconsent.Manager
}

type consentPageData struct {
	ClientID   string
	ClientName string
	Scopes     []string
	ReturnTo   string
}

func NewConsentHandler(service appconsent.Manager) *ConsentHandler {
	return &ConsentHandler{service: service}
}

func (h *ConsentHandler) Handle(c *gin.Context) {
	sessionID, _ := c.Cookie("idp_session")

	if c.Request.Method == http.MethodGet {
		returnTo := c.Query("return_to")
		result, err := h.service.Prepare(c.Request.Context(), appconsent.PrepareInput{
			ReturnTo:  returnTo,
			SessionID: sessionID,
		})
		if err != nil {
			h.writeError(c, err, returnTo)
			return
		}

		if wantsHTML(c.GetHeader("Accept")) {
			h.renderConsentPage(c, http.StatusOK, consentPageData{
				ClientID:   result.ClientID,
				ClientName: result.ClientName,
				Scopes:     result.Scopes,
				ReturnTo:   result.ReturnTo,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"endpoint":    "consent",
			"client_id":   result.ClientID,
			"client_name": result.ClientName,
			"scopes":      result.Scopes,
			"return_to":   result.ReturnTo,
			"message":     "submit action=accept or action=deny",
		})
		return
	}

	var req dto.ConsentDecisionRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid consent request"})
		return
	}

	result, err := h.service.Decide(c.Request.Context(), appconsent.DecideInput{
		ReturnTo:  req.ReturnTo,
		SessionID: sessionID,
		Action:    req.Action,
	})
	if err != nil {
		h.writeError(c, err, req.ReturnTo)
		return
	}

	c.Redirect(http.StatusFound, result.RedirectURI)
}

func wantsHTML(accept string) bool {
	accept = strings.ToLower(accept)
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

func (h *ConsentHandler) renderConsentPage(c *gin.Context, status int, data consentPageData) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = resource.ConsentPageTemplate.Execute(c.Writer, data)
}

func (h *ConsentHandler) writeError(c *gin.Context, err error, returnTo string) {
	switch {
	case errors.Is(err, appconsent.ErrLoginRequired):
		redirectTo := withReturnTo("/login", c.Request.URL.RequestURI())
		c.Redirect(http.StatusFound, redirectTo)
	case errors.Is(err, appconsent.ErrInvalidReturnTo),
		errors.Is(err, appconsent.ErrInvalidClient),
		errors.Is(err, appconsent.ErrInvalidScope),
		errors.Is(err, appconsent.ErrInvalidAction):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "return_to": returnTo})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "consent processing failed"})
	}
}
