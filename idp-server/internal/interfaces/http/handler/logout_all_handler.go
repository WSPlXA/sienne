package handler

import (
	"log"
	"net/http"
	"strings"

	appsession "idp-server/internal/application/session"
	"idp-server/internal/interfaces/http/dto"

	"github.com/gin-gonic/gin"
)

type LogoutAllHandler struct {
	service appsession.Manager
}

func NewLogoutAllHandler(service appsession.Manager) *LogoutAllHandler {
	return &LogoutAllHandler{service: service}
}

func (h *LogoutAllHandler) Handle(c *gin.Context) {
	var req dto.LogoutRequest
	if err := c.ShouldBind(&req); err != nil {
		log.Printf("logout_all bind_failed ip=%s err=%v", c.ClientIP(), err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid logout request"})
		return
	}
	validatedReturnTo, err := validateLocalRedirectTarget(req.ReturnTo)
	if err != nil {
		log.Printf("logout_all invalid_return_to ip=%s return_to=%q", c.ClientIP(), req.ReturnTo)
		c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidLocalRedirectTarget.Error()})
		return
	}
	req.ReturnTo = validatedReturnTo
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		log.Printf("logout_all csrf_validation_failed ip=%s", c.ClientIP())
		writeCSRFError(c)
		return
	}

	sessionID, _ := c.Cookie("idp_session")
	result := &appsession.LogoutAllResult{}
	if h.service != nil {
		result, err = h.service.LogoutAll(c.Request.Context(), appsession.LogoutAllInput{
			SessionID: sessionID,
		})
		if err != nil {
			log.Printf("logout_all service_failed ip=%s session_present=%t err=%v", c.ClientIP(), sessionID != "", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout all failed"})
			return
		}
	}

	c.SetCookie("idp_session", "", -1, "/", "", false, true)
	log.Printf("logout_all succeeded ip=%s session_present=%t revoked_sessions=%d revoked_access=%d revoked_refresh=%d return_to=%q",
		c.ClientIP(),
		sessionID != "",
		result.RevokedSessionCount,
		result.RevokedAccessTokens,
		result.RevokedRefreshTokens,
		req.ReturnTo,
	)

	if req.ReturnTo != "" {
		c.Redirect(http.StatusFound, req.ReturnTo)
		return
	}

	if strings.Contains(strings.ToLower(c.GetHeader("Accept")), "text/html") {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logged_out_all":         true,
		"revoked_session_count":  result.RevokedSessionCount,
		"revoked_access_tokens":  result.RevokedAccessTokens,
		"revoked_refresh_tokens": result.RevokedRefreshTokens,
	})
}
