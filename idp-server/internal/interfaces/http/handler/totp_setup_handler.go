package handler

import (
	"encoding/base64"
	"errors"
	"html/template"
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

const loginTOTPRoutingPath = "/login/totp"

type totpSetupPageData struct {
	Secret          string
	ProvisioningURI string
	QRCodeURL       template.URL
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
	// TOTP setup 页对应绑定流程的两步：
	// GET 生成 secret/二维码，POST 用用户输入的首个验证码确认启用。
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
			// 已经绑定过时不重复展示二维码，但仍要补一次登录 MFA，避免低保证级别 session 直接进入后台。
			challenge, err := h.service.BeginLoginChallenge(c.Request.Context(), sessionID, returnTo)
			if err != nil {
				h.writeError(c, err, false, returnTo)
				return
			}
			if challenge != nil && challenge.MFAChallengeID != "" {
				c.SetCookie(mfaChallengeCookieName, challenge.MFAChallengeID, 300, "/", "", false, true)
				c.SetCookie("idp_session", "", -1, "/", "", false, true)
				if wantsHTML(c.GetHeader("Accept")) {
					c.Redirect(http.StatusFound, loginTOTPRoutingPath)
					return
				}
				c.JSON(http.StatusOK, gin.H{
					"enabled":         challenge.Enabled,
					"mfa_required":    challenge.TOTPRequired,
					"challenge_id":    challenge.MFAChallengeID,
					"redirect_uri":    loginTOTPRoutingPath,
					"return_to":       returnTo,
					"already_enabled": true,
				})
				return
			}
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

	// POST 分支真正提交验证码，并可能把流程接回登录 MFA 挑战页。
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
	result, err := h.service.ConfirmSetup(c.Request.Context(), sessionID, req.Code, returnTo)
	if err != nil {
		h.writeError(c, err, true, returnTo)
		return
	}
	if result.MFAChallengeID != "" {
		// 这说明本次绑定是从“首次登录必须完成 MFA”流程里进入的，
		// 启用后还要再走一次 TOTP 登录验证。
		c.SetCookie(mfaChallengeCookieName, result.MFAChallengeID, 300, "/", "", false, true)
		c.SetCookie("idp_session", "", -1, "/", "", false, true)
		if wantsHTML(c.GetHeader("Accept")) {
			c.Redirect(http.StatusFound, loginTOTPRoutingPath)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"enabled":         result.Enabled,
			"mfa_required":    result.TOTPRequired,
			"challenge_id":    result.MFAChallengeID,
			"redirect_uri":    loginTOTPRoutingPath,
			"return_to":       returnTo,
			"already_enabled": false,
		})
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
	// HTML/JSON 双模输出都共用这一个 render，避免不同响应模式的数据漂移。
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
		"qr_code_url":      string(data.QRCodeURL),
		"return_to":        data.ReturnTo,
		"already_enabled":  data.AlreadyEnabled,
		"enabled":          data.Success,
		"csrf_token":       data.CSRFToken,
		"error":            data.Error,
	})
}

func (h *TOTPSetupHandler) writeError(c *gin.Context, err error, preserve bool, returnTo string) {
	// preserve=true 时会重新拉一份 enrollment 数据，方便用户在验证码输错后继续当前二维码。
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
	case errors.Is(err, appmfa.ErrEnrollmentExpired), errors.Is(err, appmfa.ErrInvalidTOTPCode), errors.Is(err, appmfa.ErrTOTPCodeReused):
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

func buildQRCodeURL(provisioningURI string) template.URL {
	// 直接把 QR PNG 编码成 data URL，避免额外的静态文件或动态图片路由。
	provisioningURI = strings.TrimSpace(provisioningURI)
	if provisioningURI == "" {
		return ""
	}
	png, err := qrcode.Encode(provisioningURI, qrcode.Medium, 220)
	if err != nil || len(png) == 0 {
		return ""
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
}
