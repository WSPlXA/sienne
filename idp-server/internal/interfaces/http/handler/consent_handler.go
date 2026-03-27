package handler

import (
	"errors"
	"log"
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
	CSRFToken  string
	Error      string
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
			log.Printf("consent prepare_failed ip=%s session_present=%t return_to=%q err=%v", c.ClientIP(), sessionID != "", returnTo, err)
			h.writeError(c, err, returnTo)
			return
		}

		csrfToken, err := ensureCSRFToken(c)
		if err != nil {
			log.Printf("consent csrf_issue_failed ip=%s session_present=%t err=%v", c.ClientIP(), sessionID != "", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
			return
		}
		log.Printf("consent prepare_succeeded ip=%s session_present=%t client_id=%q scopes=%d", c.ClientIP(), sessionID != "", result.ClientID, len(result.Scopes))

		if wantsHTML(c.GetHeader("Accept")) {
			h.renderConsentPage(c, http.StatusOK, consentPageData{
				ClientID:   result.ClientID,
				ClientName: result.ClientName,
				Scopes:     result.Scopes,
				ReturnTo:   result.ReturnTo,
				CSRFToken:  csrfToken,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"endpoint":    "consent",
			"client_id":   result.ClientID,
			"client_name": result.ClientName,
			"scopes":      result.Scopes,
			"csrf_token":  csrfToken,
			"return_to":   result.ReturnTo,
			"message":     "submit action=accept or action=deny",
		})
		return
	}

	var req dto.ConsentDecisionRequest
	if err := c.ShouldBind(&req); err != nil {
		log.Printf("consent bind_failed ip=%s session_present=%t err=%v", c.ClientIP(), sessionID != "", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid consent request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		log.Printf("consent csrf_validation_failed ip=%s session_present=%t action=%q return_to=%q", c.ClientIP(), sessionID != "", req.Action, req.ReturnTo)
		h.writeCSRFFailure(c, req.ReturnTo, sessionID)
		return
	}

	result, err := h.service.Decide(c.Request.Context(), appconsent.DecideInput{
		ReturnTo:  req.ReturnTo,
		SessionID: sessionID,
		Action:    req.Action,
	})
	if err != nil {
		log.Printf("consent decide_failed ip=%s session_present=%t action=%q return_to=%q err=%v", c.ClientIP(), sessionID != "", req.Action, req.ReturnTo, err)
		h.writeError(c, err, req.ReturnTo)
		return
	}

	log.Printf("consent decide_succeeded ip=%s session_present=%t action=%q redirect_uri=%q", c.ClientIP(), sessionID != "", req.Action, result.RedirectURI)
	c.Redirect(http.StatusFound, result.RedirectURI)
}

func wantsHTML(accept string) bool {
	accept = strings.ToLower(accept)
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

func (h *ConsentHandler) renderConsentPage(c *gin.Context, status int, data consentPageData) {
	if data.CSRFToken == "" {
		csrfToken, err := ensureCSRFToken(c)
		if err != nil {
			log.Printf("consent render_failed ip=%s err=%v", c.ClientIP(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
			return
		}
		data.CSRFToken = csrfToken
	}
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

func (h *ConsentHandler) writeCSRFFailure(c *gin.Context, returnTo, sessionID string) {
	if wantsHTML(c.GetHeader("Accept")) {
		data := consentPageData{
			ReturnTo: returnTo,
			Error:    "リクエストの整合性検証に失敗しました。",
		}
		if h.service != nil {
			result, err := h.service.Prepare(c.Request.Context(), appconsent.PrepareInput{
				ReturnTo:  returnTo,
				SessionID: sessionID,
			})
			if err == nil && result != nil {
				data.ClientID = result.ClientID
				data.ClientName = result.ClientName
				data.Scopes = result.Scopes
				data.ReturnTo = result.ReturnTo
			}
		}
		h.renderConsentPage(c, http.StatusForbidden, data)
		return
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error(), "return_to": returnTo})
}
