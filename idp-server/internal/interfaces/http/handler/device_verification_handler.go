package handler

import (
	"errors"
	"net/http"
	"net/url"

	appdevice "idp-server/internal/application/device"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type DeviceVerificationHandler struct {
	verifier appdevice.Verifier
}

type devicePageData struct {
	UserCode   string
	ClientID   string
	ClientName string
	Scopes     []string
	CSRFToken  string
	Error      string
	Success    bool
}

func NewDeviceVerificationHandler(verifier appdevice.Verifier) *DeviceVerificationHandler {
	return &DeviceVerificationHandler{verifier: verifier}
}

func (h *DeviceVerificationHandler) Handle(c *gin.Context) {
	// 这是 device flow 的“浏览器端确认页”：
	// 用户在这里输入或确认 user_code，然后决定 approve / deny。
	sessionID, _ := c.Cookie("idp_session")

	if c.Request.Method == http.MethodGet {
		// GET 用于展示确认页面；如果已带 user_code，就先尝试解析成待授权上下文。
		userCode := c.Query("user_code")
		if userCode == "" {
			h.renderPage(c, http.StatusOK, devicePageData{})
			return
		}
		result, err := h.verifier.Prepare(c.Request.Context(), appdevice.PrepareInput{
			SessionID: sessionID,
			UserCode:  userCode,
		})
		if err != nil {
			h.writeError(c, err, userCode)
			return
		}
		h.renderPage(c, http.StatusOK, devicePageData{
			UserCode:   result.UserCode,
			ClientID:   result.ClientID,
			ClientName: result.ClientName,
			Scopes:     result.Scopes,
		})
		return
	}

	// POST 分支真正提交用户决策。
	var req dto.DeviceVerifyRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid verification request"})
		return
	}
	if req.Action == "" {
		// 没有 action 时退回 GET 展示页，保留 user_code。
		c.Redirect(http.StatusFound, "/device?user_code="+url.QueryEscape(req.UserCode))
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		h.renderPage(c, http.StatusForbidden, devicePageData{
			UserCode: req.UserCode,
			Error:    "CSRF validation failed.",
		})
		return
	}

	result, err := h.verifier.Decide(c.Request.Context(), appdevice.DecideInput{
		SessionID: sessionID,
		UserCode:  req.UserCode,
		Action:    req.Action,
	})
	if err != nil {
		h.writeError(c, err, req.UserCode)
		return
	}
	h.renderPage(c, http.StatusOK, devicePageData{
		UserCode: req.UserCode,
		Success:  true,
		Error:    successMessage(result.Approved),
	})
}

func (h *DeviceVerificationHandler) renderPage(c *gin.Context, status int, data devicePageData) {
	// 设备确认页同样兼容 HTML 和 JSON 两种输出模式。
	csrfToken, err := ensureCSRFToken(c)
	if err == nil {
		data.CSRFToken = csrfToken
	}
	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.DevicePageTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, data)
}

func (h *DeviceVerificationHandler) writeError(c *gin.Context, err error, userCode string) {
	// 未登录时把用户送去登录页，并在 return_to 里保留当前 user_code。
	switch {
	case errors.Is(err, appdevice.ErrLoginRequired):
		c.Redirect(http.StatusFound, withReturnTo("/login", "/device?user_code="+url.QueryEscape(userCode)))
	case errors.Is(err, appdevice.ErrInvalidUserCode), errors.Is(err, appdevice.ErrInvalidAction):
		h.renderPage(c, http.StatusBadRequest, devicePageData{
			UserCode: userCode,
			Error:    err.Error(),
		})
	default:
		h.renderPage(c, http.StatusInternalServerError, devicePageData{
			UserCode: userCode,
			Error:    "device verification failed",
		})
	}
}

func successMessage(approved bool) string {
	// 成功文案的重点是提醒用户“回到原设备继续”，因为真正消费结果的是轮询端。
	if approved {
		return "Device verification approved. Return to your original device to continue."
	}
	return "Device verification denied."
}
