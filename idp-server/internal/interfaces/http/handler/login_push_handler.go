package handler

import (
	"errors"
	"net/http"
	"strings"

	"idp-server/internal/application/authn"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type LoginPushHandler struct {
	authnService authn.Authenticator
}

type loginPushPageData struct {
	CSRFToken   string
	ChallengeID string
	MatchCode   string
	Status      string
	Error       string
}

func NewLoginPushHandler(authnService authn.Authenticator) *LoginPushHandler {
	return &LoginPushHandler{authnService: authnService}
}

func (h *LoginPushHandler) Handle(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		h.render(c, http.StatusOK, loginPushPageData{
			ChallengeID: strings.TrimSpace(c.Query("challenge_id")),
			MatchCode:   strings.TrimSpace(c.Query("match_code")),
		})
		return
	}

	var req dto.LoginTOTPRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid push approval request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		h.render(c, http.StatusForbidden, loginPushPageData{
			ChallengeID: req.ChallengeID,
			MatchCode:   req.MatchCode,
			Error:       errInvalidCSRFToken.Error(),
		})
		return
	}

	sessionID, _ := c.Cookie("idp_session")
	result, err := h.authnService.DecideMFAPush(c.Request.Context(), authn.DecideMFAPushInput{
		ChallengeID:       req.ChallengeID,
		ApproverSessionID: sessionID,
		Action:            req.Action,
		MatchCode:         req.MatchCode,
		IPAddress:         c.ClientIP(),
		UserAgent:         c.GetHeader("User-Agent"),
	})
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, authn.ErrMFAApproverMismatch):
			status = http.StatusForbidden
		case errors.Is(err, authn.ErrMFAChallengeExpired):
			status = http.StatusUnauthorized
		case errors.Is(err, authn.ErrInvalidPushMatchCode), errors.Is(err, authn.ErrInvalidMFAAction):
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}
		h.render(c, status, loginPushPageData{
			ChallengeID: req.ChallengeID,
			MatchCode:   req.MatchCode,
			Error:       err.Error(),
		})
		return
	}

	if wantsHTML(c.GetHeader("Accept")) {
		h.render(c, http.StatusOK, loginPushPageData{
			ChallengeID: req.ChallengeID,
			MatchCode:   req.MatchCode,
			Status:      result.PushStatus,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"challenge_id": result.ChallengeID,
		"mfa_mode":     result.MFAMode,
		"push_status":  result.PushStatus,
		"push_code":    result.PushCode,
		"expires_at":   result.ExpiresAt,
	})
}

func (h *LoginPushHandler) render(c *gin.Context, status int, data loginPushPageData) {
	if token, err := ensureCSRFToken(c); err == nil {
		data.CSRFToken = token
	}
	if wantsHTML(c.GetHeader("Accept")) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(status)
		_ = resource.LoginPushTemplate.Execute(c.Writer, data)
		return
	}
	c.JSON(status, gin.H{
		"csrf_token":   data.CSRFToken,
		"challenge_id": data.ChallengeID,
		"match_code":   data.MatchCode,
		"status":       data.Status,
		"error":        data.Error,
	})
}
