package handler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	appmfa "idp-server/internal/application/mfa"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
	qrcode "github.com/skip2/go-qrcode"
)

type TOTPSetupHandler struct {
	service appmfa.Manager
}

type totpSetupPageData struct {
	Secret          string
	ProvisioningURI string
	QRCodeURL       string
	ReturnTo        string
	CSRFToken       string
	Error           string
	Success         bool
	AlreadyEnabled  bool
}

func NewTOTPSetupHandler(service appmfa.Manager) *TOTPSetupHandler {
	return &TOTPSetupHandler{service: service}
}

func (h *TOTPSetupHandler) Handle(c *gin.Context) {
	sessionID, _ := c.Cookie("idp_session")
	returnTo, err := validateLocalRedirectTarget(strings.TrimSpace(c.Query("return_to")))
	if err != nil {
		if wantsHTML(c.GetHeader("Accept")) {
			h.render(c, http.StatusBadRequest, totpSetupPageData{Error: errInvalidLocalRedirectTarget.Error()})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidLocalRedirectTarget.Error()})
		return
	}
	if c.Request.Method == http.MethodGet {
		result, err := h.service.BeginSetup(c.Request.Context(), sessionID)
		if err != nil {
			h.writeError(c, err, false, returnTo)
			return
		}
		if result.AlreadyEnabled && returnTo != "" {
			c.Redirect(http.StatusFound, returnTo)
			return
		}
		h.render(c, http.StatusOK, totpSetupPageData{
			Secret:          result.Secret,
			ProvisioningURI: result.ProvisioningURI,
			QRCodeURL:       buildQRCodeURL(result.ProvisioningURI),
			ReturnTo:        returnTo,
			AlreadyEnabled:  result.AlreadyEnabled,
		})
		return
	}

	var req dto.TOTPSetupRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid totp setup request"})
		return
	}
	if reqReturnToRaw := strings.TrimSpace(req.ReturnTo); reqReturnToRaw != "" {
		reqReturnTo, err := validateLocalRedirectTarget(reqReturnToRaw)
		if err != nil {
			if wantsHTML(c.GetHeader("Accept")) {
				h.render(c, http.StatusBadRequest, totpSetupPageData{Error: errInvalidLocalRedirectTarget.Error(), ReturnTo: returnTo})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidLocalRedirectTarget.Error()})
			return
		}
		returnTo = reqReturnTo
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		h.render(c, http.StatusForbidden, totpSetupPageData{Error: errInvalidCSRFToken.Error(), ReturnTo: returnTo})
		return
	}
	result, err := h.service.ConfirmSetup(c.Request.Context(), sessionID, req.Code)
	if err != nil {
		h.writeError(c, err, true, returnTo)
		return
	}
	if result.Enabled && returnTo != "" {
		c.Redirect(http.StatusFound, returnTo)
		return
	}
	h.render(c, http.StatusOK, totpSetupPageData{
		Success:  result.Enabled,
		ReturnTo: returnTo,
		Error:    "TOTP has been enabled.",
	})
}

func (h *TOTPSetupHandler) render(c *gin.Context, status int, data totpSetupPageData) {
	if token, err := ensureCSRFToken(c); err == nil {
		data.CSRFToken = token
	}
	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.TOTPSetupTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, gin.H{
		"secret":           data.Secret,
		"provisioning_uri": data.ProvisioningURI,
		"qr_code_url":      data.QRCodeURL,
		"return_to":        data.ReturnTo,
		"already_enabled":  data.AlreadyEnabled,
		"enabled":          data.Success,
		"csrf_token":       data.CSRFToken,
		"error":            data.Error,
	})
}

func (h *TOTPSetupHandler) writeError(c *gin.Context, err error, preserve bool, returnTo string) {
	status := http.StatusInternalServerError
	data := totpSetupPageData{ReturnTo: returnTo}
	setupPath := "/mfa/totp/setup"
	if returnTo != "" {
		setupPath = withReturnTo(setupPath, returnTo)
	}
	switch {
	case errors.Is(err, appmfa.ErrLoginRequired):
		c.Redirect(http.StatusFound, withReturnTo("/login", setupPath))
		return
	case errors.Is(err, appmfa.ErrAlreadyEnabled):
		status = http.StatusConflict
		data.AlreadyEnabled = true
		data.Error = err.Error()
	case errors.Is(err, appmfa.ErrEnrollmentExpired), errors.Is(err, appmfa.ErrInvalidTOTPCode):
		status = http.StatusBadRequest
		data.Error = err.Error()
	default:
		data.Error = "totp setup failed"
	}
	if preserve && status == http.StatusBadRequest {
		sessionID, _ := c.Cookie("idp_session")
		if result, beginErr := h.service.BeginSetup(c.Request.Context(), sessionID); beginErr == nil && result != nil {
			data.Secret = result.Secret
			data.ProvisioningURI = result.ProvisioningURI
			data.QRCodeURL = buildQRCodeURL(result.ProvisioningURI)
			data.ReturnTo = returnTo
			data.AlreadyEnabled = result.AlreadyEnabled
		}
	}
	h.render(c, status, data)
}

func buildQRCodeURL(provisioningURI string) string {
	provisioningURI = strings.TrimSpace(provisioningURI)
	if provisioningURI == "" {
		return ""
	}
	png, err := qrcode.Encode(provisioningURI, qrcode.Medium, 220)
	if err != nil || len(png) == 0 {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}
