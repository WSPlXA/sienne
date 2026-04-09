package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	apppasskey "idp-server/internal/application/passkey"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

const passkeySetupRoutingPath = "/mfa/passkey/setup"

type PasskeySetupHandler struct {
	service apppasskey.Manager
}

type passkeySetupPageData struct {
	CSRFToken string
	ReturnTo  string
	Error     string
	Success   bool
}

func NewPasskeySetupHandler(service apppasskey.Manager) *PasskeySetupHandler {
	return &PasskeySetupHandler{service: service}
}

func (h *PasskeySetupHandler) Handle(c *gin.Context) {
	sessionID, _ := c.Cookie("idp_session")
	returnTo, err := validateLocalRedirectTarget(strings.TrimSpace(c.Query("return_to")))
	if err != nil {
		h.render(c, http.StatusBadRequest, passkeySetupPageData{
			Error: errInvalidLocalRedirectTarget.Error(),
		})
		return
	}

	if c.Request.Method == http.MethodGet {
		h.render(c, http.StatusOK, passkeySetupPageData{ReturnTo: returnTo})
		return
	}

	var req dto.PasskeySetupRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid passkey setup request"})
		return
	}
	if reqReturnToRaw := strings.TrimSpace(req.ReturnTo); reqReturnToRaw != "" {
		reqReturnTo, err := validateLocalRedirectTarget(reqReturnToRaw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidLocalRedirectTarget.Error()})
			return
		}
		returnTo = reqReturnTo
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error()})
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	switch action {
	case "begin":
		h.handleBegin(c, sessionID, returnTo)
		return
	case "finish":
		h.handleFinish(c, sessionID, returnTo, req)
		return
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid passkey setup action"})
		return
	}
}

func (h *PasskeySetupHandler) handleBegin(c *gin.Context, sessionID, returnTo string) {
	if h.service == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": apppasskey.ErrPasskeyDisabled.Error()})
		return
	}
	result, err := h.service.BeginSetup(c.Request.Context(), sessionID)
	if err != nil {
		h.writeError(c, err, returnTo)
		return
	}
	var options any
	if err := json.Unmarshal(result.OptionsJSON, &options); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid passkey options payload"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"setup_id":   result.SetupID,
		"options":    options,
		"expires_at": result.ExpiresAt,
		"return_to":  returnTo,
	})
}

func (h *PasskeySetupHandler) handleFinish(c *gin.Context, sessionID, returnTo string, req dto.PasskeySetupRequest) {
	if h.service == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": apppasskey.ErrPasskeyDisabled.Error()})
		return
	}
	setupID := strings.TrimSpace(req.SetupID)
	responseJSON := strings.TrimSpace(req.ResponseJSON)
	if setupID == "" || responseJSON == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing setup_id or response_json"})
		return
	}
	_, err := h.service.FinishSetup(c.Request.Context(), sessionID, setupID, []byte(responseJSON))
	if err != nil {
		h.writeError(c, err, returnTo)
		return
	}
	redirectURI := returnTo
	if redirectURI == "" {
		redirectURI = defaultPostLoginRedirect
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled":      true,
		"redirect_uri": redirectURI,
		"return_to":    returnTo,
	})
}

func (h *PasskeySetupHandler) writeError(c *gin.Context, err error, returnTo string) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, apppasskey.ErrLoginRequired):
		loginReturn := passkeySetupRoutingPath
		if returnTo != "" {
			loginReturn = withReturnTo(passkeySetupRoutingPath, returnTo)
		}
		if wantsHTML(c.GetHeader("Accept")) {
			c.Redirect(http.StatusFound, withReturnTo("/login", loginReturn))
			return
		}
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":        err.Error(),
			"redirect_uri": withReturnTo("/login", loginReturn),
		})
		return
	case errors.Is(err, apppasskey.ErrPasskeyDisabled):
		status = http.StatusServiceUnavailable
	case errors.Is(err, apppasskey.ErrPasskeySetupExpired):
		status = http.StatusUnauthorized
	case errors.Is(err, apppasskey.ErrPasskeyCredentialSave):
		status = http.StatusInternalServerError
	}
	c.JSON(status, gin.H{
		"error":     err.Error(),
		"return_to": returnTo,
	})
}

func (h *PasskeySetupHandler) render(c *gin.Context, status int, data passkeySetupPageData) {
	if token, err := ensureCSRFToken(c); err == nil {
		data.CSRFToken = token
	}
	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.PasskeySetupTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, gin.H{
		"csrf_token": data.CSRFToken,
		"return_to":  data.ReturnTo,
		"error":      data.Error,
		"success":    data.Success,
	})
}
