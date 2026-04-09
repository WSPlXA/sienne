package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"idp-server/internal/application/authn"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

const mfaChallengeCookieName = "idp_mfa_challenge"

type LoginTOTPHandler struct {
	authnService authn.Authenticator
}

const defaultPostLoginRedirect = "/"

type loginTOTPPageData struct {
	CSRFToken   string
	Error       string
	ChallengeID string
	PushEnabled bool
	PushStatus  string
	PushCode    string
}

func NewLoginTOTPHandler(authnService authn.Authenticator) *LoginTOTPHandler {
	return &LoginTOTPHandler{authnService: authnService}
}

func (h *LoginTOTPHandler) Handle(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		if strings.EqualFold(strings.TrimSpace(c.Query("mode")), "status") {
			h.writePushStatus(c)
			return
		}
		data := h.loadChallengeData(c)
		h.render(c, http.StatusOK, data)
		return
	}
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
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		data := h.loadChallengeData(c)
		data.Error = errInvalidCSRFToken.Error()
		h.render(c, http.StatusForbidden, data)
		return
	}
	challengeID, _ := c.Cookie(mfaChallengeCookieName)
	result, err := h.authnService.VerifyTOTP(c.Request.Context(), authn.VerifyTOTPInput{
		ChallengeID: challengeID,
		Code:        req.Code,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
	})
	if err != nil {
		status := http.StatusUnauthorized
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
	redirectURI := result.ReturnTo
	if redirectURI == "" {
		redirectURI = result.RedirectURI
	}
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

func (h *LoginTOTPHandler) handlePushDecision(c *gin.Context, req dto.LoginTOTPRequest) {
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
		status := http.StatusBadRequest
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
		status := http.StatusUnauthorized
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
			redirectURI := result.ReturnTo
			if redirectURI == "" {
				redirectURI = result.RedirectURI
			}
			if redirectURI == "" {
				redirectURI = defaultPostLoginRedirect
			}
			c.JSON(http.StatusOK, gin.H{
				"authenticated": true,
				"status":        authn.MFAPushStatusApproved,
				"redirect_uri":  redirectURI,
				"session_id":    result.SessionID,
				"user_id":       result.UserID,
				"subject":       result.Subject,
				"expires_at":    result.ExpiresAt,
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"authenticated": false,
		"challenge_id":  state.ChallengeID,
		"mfa_mode":      state.MFAMode,
		"push_status":   state.PushStatus,
		"push_code":     state.PushCode,
		"expires_at":    state.ExpiresAt,
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
		"csrf_token":   data.CSRFToken,
		"error":        data.Error,
		"challenge_id": data.ChallengeID,
		"push_enabled": data.PushEnabled,
		"push_status":  data.PushStatus,
		"push_code":    data.PushCode,
	})
}
