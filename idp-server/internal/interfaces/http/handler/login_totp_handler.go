package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"idp-server/internal/application/authn"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/internal/ports/repository"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

const mfaChallengeCookieName = "idp_mfa_challenge"

type LoginTOTPHandler struct {
	authnService authn.Authenticator
	auditRepo    repository.AuditEventRepository
}

const defaultPostLoginRedirect = "/"

type loginTOTPPageData struct {
	CSRFToken      string
	Error          string
	ChallengeID    string
	PushEnabled    bool
	PasskeyEnabled bool
	PushStatus     string
	PushCode       string
}

func NewLoginTOTPHandler(authnService authn.Authenticator, auditRepo ...repository.AuditEventRepository) *LoginTOTPHandler {
	var repo repository.AuditEventRepository
	if len(auditRepo) > 0 {
		repo = auditRepo[0]
	}
	return &LoginTOTPHandler{authnService: authnService, auditRepo: repo}
}

func (h *LoginTOTPHandler) Handle(c *gin.Context) {
	// LoginTOTPHandler 承担“登录第二要素页”的多种动作：
	// 展示挑战状态、校验 TOTP、处理 Passkey MFA，以及 Push MFA 的轮询/批准。
	if c.Request.Method == http.MethodGet {
		if strings.EqualFold(strings.TrimSpace(c.Query("mode")), "status") {
			h.writePushStatus(c)
			return
		}
		data := h.loadChallengeData(c)
		h.render(c, http.StatusOK, data)
		return
	}
	// POST 请求里的 action 会决定进入哪条 MFA 分支；
	// 默认分支则是最常见的 TOTP 提交。
	var req dto.LoginTOTPRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid totp login request"})
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	switch action {
	case "approve", "deny":
		h.handlePushDecision(c, req)
		return
	case "poll":
		h.writePushStatus(c)
		return
	case "passkey_begin":
		if err := validateCSRFToken(c, req.CSRFToken); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error()})
			return
		}
		h.handlePasskeyBegin(c, req)
		return
	case "passkey_finish":
		if err := validateCSRFToken(c, req.CSRFToken); err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error()})
			return
		}
		h.handlePasskeyFinish(c, req)
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		data := h.loadChallengeData(c)
		data.Error = errInvalidCSRFToken.Error()
		h.render(c, http.StatusForbidden, data)
		return
	}
	challengeID, _ := c.Cookie(mfaChallengeCookieName)
	// 这里消费的是登录第一阶段留下来的 challenge cookie，
	// 成功后才会正式补发 idp_session。
	result, err := h.authnService.VerifyTOTP(c.Request.Context(), authn.VerifyTOTPInput{
		ChallengeID: challengeID,
		Code:        req.Code,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
	})
	if err != nil {
		var status int
		switch {
		case errors.Is(err, authn.ErrMFAChallengeExpired):
			status = http.StatusUnauthorized
			c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
		case errors.Is(err, authn.ErrInvalidTOTPCode), errors.Is(err, authn.ErrTOTPCodeReused):
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
		}
		data := h.loadChallengeData(c)
		data.Error = err.Error()
		h.render(c, status, data)
		return
	}
	c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
	maxAge := int(time.Until(result.ExpiresAt).Seconds())
	c.SetCookie("idp_session", result.SessionID, maxAge, "/", "", false, true)
	if result.MFAEnrollmentRequired {
		targetReturnTo := resolveBrowserPostLoginRedirect(result.ReturnTo, result.RedirectURI, result.RoleCode)
		setupURI := buildMFASetupURI(targetReturnTo)
		if wantsHTML(c.GetHeader("Accept")) {
			c.Redirect(http.StatusFound, setupURI)
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"session_id":               result.SessionID,
			"user_id":                  result.UserID,
			"subject":                  result.Subject,
			"expires_at":               result.ExpiresAt,
			"mfa_enrollment_required":  true,
			"passkey_enrollment_first": true,
			"redirect_uri":             setupURI,
		})
		return
	}
	redirectURI := resolveBrowserPostLoginRedirect(result.ReturnTo, result.RedirectURI, result.RoleCode)
	recordLoginSuccessAuditEvent(c.Request.Context(), h.auditRepo, c, result.UserID, result.Subject, result.RoleCode, "totp", redirectURI)
	if redirectURI != "" {
		c.Redirect(http.StatusFound, redirectURI)
		return
	}
	if wantsHTML(c.GetHeader("Accept")) {
		c.Redirect(http.StatusFound, defaultPostLoginRedirect)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"session_id": result.SessionID,
		"user_id":    result.UserID,
		"subject":    result.Subject,
		"expires_at": result.ExpiresAt,
	})
}

func (h *LoginTOTPHandler) handlePasskeyBegin(c *gin.Context, req dto.LoginTOTPRequest) {
	// Passkey MFA 登录同样分 begin/finish 两步，对应 WebAuthn challenge 的发起与回收。
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		challengeID, _ = c.Cookie(mfaChallengeCookieName)
	}
	result, err := h.authnService.BeginMFAPasskey(c.Request.Context(), authn.BeginMFAPasskeyInput{
		ChallengeID: challengeID,
	})
	if err != nil {
		var status int
		switch {
		case errors.Is(err, authn.ErrMFAChallengeExpired):
			status = http.StatusUnauthorized
			c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
		case errors.Is(err, authn.ErrPasskeyUnavailable), errors.Is(err, authn.ErrPasskeySessionMissing):
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	var options any
	if err := json.Unmarshal(result.OptionsJSON, &options); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid passkey options payload"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"challenge_id": result.ChallengeID,
		"options":      options,
		"expires_at":   result.ExpiresAt,
	})
}

func (h *LoginTOTPHandler) handlePasskeyFinish(c *gin.Context, req dto.LoginTOTPRequest) {
	// Finish 成功后就可以像 TOTP 一样正式创建本地会话。
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		challengeID, _ = c.Cookie(mfaChallengeCookieName)
	}
	responseJSON := strings.TrimSpace(req.ResponseJSON)
	if responseJSON == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing passkey response payload"})
		return
	}
	result, err := h.authnService.VerifyMFAPasskey(c.Request.Context(), authn.VerifyMFAPasskeyInput{
		ChallengeID:  challengeID,
		ResponseJSON: []byte(responseJSON),
	})
	if err != nil {
		var status int
		switch {
		case errors.Is(err, authn.ErrMFAChallengeExpired):
			status = http.StatusUnauthorized
			c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
		case errors.Is(err, authn.ErrPasskeyUnavailable), errors.Is(err, authn.ErrPasskeySessionMissing), errors.Is(err, authn.ErrInvalidCredentials):
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
	maxAge := int(time.Until(result.ExpiresAt).Seconds())
	c.SetCookie("idp_session", result.SessionID, maxAge, "/", "", false, true)
	redirectURI := resolveBrowserPostLoginRedirect(result.ReturnTo, result.RedirectURI, result.RoleCode)
	if redirectURI == "" {
		redirectURI = defaultPostLoginRedirect
	}
	recordLoginSuccessAuditEvent(c.Request.Context(), h.auditRepo, c, result.UserID, result.Subject, result.RoleCode, "passkey", redirectURI)
	c.JSON(http.StatusOK, gin.H{
		"authenticated": true,
		"redirect_uri":  redirectURI,
		"session_id":    result.SessionID,
		"user_id":       result.UserID,
		"subject":       result.Subject,
		"expires_at":    result.ExpiresAt,
	})
}

func (h *LoginTOTPHandler) handlePushDecision(c *gin.Context, req dto.LoginTOTPRequest) {
	// Push MFA 的 approve/deny 由已登录设备来做，因此这里还会带上 approver 的 session。
	challengeID := strings.TrimSpace(req.ChallengeID)
	if challengeID == "" {
		challengeID, _ = c.Cookie(mfaChallengeCookieName)
	}
	sessionID, _ := c.Cookie("idp_session")
	state, err := h.authnService.DecideMFAPush(c.Request.Context(), authn.DecideMFAPushInput{
		ChallengeID:       challengeID,
		ApproverSessionID: sessionID,
		Action:            req.Action,
		MatchCode:         req.MatchCode,
		IPAddress:         c.ClientIP(),
		UserAgent:         c.GetHeader("User-Agent"),
	})
	if err != nil {
		var status int
		switch {
		case errors.Is(err, authn.ErrMFAChallengeExpired):
			status = http.StatusUnauthorized
		case errors.Is(err, authn.ErrMFAApproverMismatch):
			status = http.StatusForbidden
		case errors.Is(err, authn.ErrInvalidPushMatchCode), errors.Is(err, authn.ErrInvalidMFAAction):
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"challenge_id": state.ChallengeID,
		"mfa_mode":     state.MFAMode,
		"push_status":  state.PushStatus,
		"push_code":    state.PushCode,
		"expires_at":   state.ExpiresAt,
	})
}

func (h *LoginTOTPHandler) writePushStatus(c *gin.Context) {
	// 轮询接口除了返回 push 状态外，在审批通过时还会顺手 finalize 挑战并补发 session。
	challengeID, _ := c.Cookie(mfaChallengeCookieName)
	challengeID = strings.TrimSpace(challengeID)
	if challengeID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "missing mfa challenge cookie",
		})
		return
	}
	state, err := h.authnService.PollMFAChallenge(c.Request.Context(), authn.PollMFAChallengeInput{
		ChallengeID: challengeID,
	})
	if err != nil {
		var status int
		if errors.Is(err, authn.ErrMFAChallengeExpired) {
			c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
			status = http.StatusUnauthorized
		} else {
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	if state.MFAMode == authn.MFAModePushTOTPFallback && state.PushStatus == authn.MFAPushStatusApproved {
		result, err := h.authnService.FinalizeMFAPush(c.Request.Context(), authn.FinalizeMFAPushInput{
			ChallengeID: challengeID,
		})
		if err == nil {
			c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
			maxAge := int(time.Until(result.ExpiresAt).Seconds())
			c.SetCookie("idp_session", result.SessionID, maxAge, "/", "", false, true)
			redirectURI := resolveBrowserPostLoginRedirect(result.ReturnTo, result.RedirectURI, result.RoleCode)
			if redirectURI == "" {
				redirectURI = defaultPostLoginRedirect
			}
			recordLoginSuccessAuditEvent(c.Request.Context(), h.auditRepo, c, result.UserID, result.Subject, result.RoleCode, "push", redirectURI)
			c.JSON(http.StatusOK, gin.H{
				"authenticated":     true,
				"status":            authn.MFAPushStatusApproved,
				"passkey_available": state.PasskeyAvailable,
				"redirect_uri":      redirectURI,
				"session_id":        result.SessionID,
				"user_id":           result.UserID,
				"subject":           result.Subject,
				"expires_at":        result.ExpiresAt,
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated":     false,
		"challenge_id":      state.ChallengeID,
		"mfa_mode":          state.MFAMode,
		"passkey_available": state.PasskeyAvailable,
		"push_status":       state.PushStatus,
		"push_code":         state.PushCode,
		"expires_at":        state.ExpiresAt,
	})
}

func (h *LoginTOTPHandler) loadChallengeData(c *gin.Context) loginTOTPPageData {
	challengeID, _ := c.Cookie(mfaChallengeCookieName)
	challengeID = strings.TrimSpace(challengeID)
	data := loginTOTPPageData{
		ChallengeID: challengeID,
	}
	if challengeID == "" {
		return data
	}
	state, err := h.authnService.PollMFAChallenge(c.Request.Context(), authn.PollMFAChallengeInput{
		ChallengeID: challengeID,
	})
	if err != nil {
		if errors.Is(err, authn.ErrMFAChallengeExpired) {
			c.SetCookie(mfaChallengeCookieName, "", -1, "/", "", false, true)
		}
		return data
	}
	data.ChallengeID = state.ChallengeID
	data.PushEnabled = state.MFAMode == authn.MFAModePushTOTPFallback
	data.PasskeyEnabled = state.PasskeyAvailable
	data.PushStatus = state.PushStatus
	data.PushCode = state.PushCode
	return data
}

func (h *LoginTOTPHandler) render(c *gin.Context, status int, data loginTOTPPageData) {
	if token, err := ensureCSRFToken(c); err == nil {
		data.CSRFToken = token
	}
	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.LoginTOTPTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, gin.H{
		"csrf_token":      data.CSRFToken,
		"error":           data.Error,
		"challenge_id":    data.ChallengeID,
		"push_enabled":    data.PushEnabled,
		"passkey_enabled": data.PasskeyEnabled,
		"push_status":     data.PushStatus,
		"push_code":       data.PushCode,
	})
}
