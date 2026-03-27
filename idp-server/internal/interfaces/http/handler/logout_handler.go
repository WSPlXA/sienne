package handler

import (
	"log"
	"net/http"
	"strings"

	appsession "idp-server/internal/application/session"
	"idp-server/internal/interfaces/http/dto"

	"github.com/gin-gonic/gin"
)

type LogoutHandler struct {
	service appsession.Manager
}

func NewLogoutHandler(service appsession.Manager) *LogoutHandler {
	return &LogoutHandler{service: service}
}

func (h *LogoutHandler) Handle(c *gin.Context) {
	var req dto.LogoutRequest
	if err := c.ShouldBind(&req); err != nil {
		log.Printf("logout bind_failed ip=%s err=%v", c.ClientIP(), err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid logout request"})
		return
	}
	validatedReturnTo, err := validateLocalRedirectTarget(req.ReturnTo)
	if err != nil {
		log.Printf("logout invalid_return_to ip=%s return_to=%q", c.ClientIP(), req.ReturnTo)
		c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidLocalRedirectTarget.Error()})
		return
	}
	req.ReturnTo = validatedReturnTo
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		log.Printf("logout csrf_validation_failed ip=%s", c.ClientIP())
		writeCSRFError(c)
		return
	}

	sessionID, _ := c.Cookie("idp_session")
	if h.service != nil {
		if _, err := h.service.Logout(c.Request.Context(), appsession.LogoutInput{
			SessionID: sessionID,
		}); err != nil {
			log.Printf("logout service_failed ip=%s session_present=%t err=%v", c.ClientIP(), sessionID != "", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
			return
		}
	}

	c.SetCookie("idp_session", "", -1, "/", "", false, true)
	log.Printf("logout succeeded ip=%s session_present=%t return_to=%q", c.ClientIP(), sessionID != "", req.ReturnTo)

	if req.ReturnTo != "" {
		c.Redirect(http.StatusFound, req.ReturnTo)
		return
	}

	if strings.Contains(strings.ToLower(c.GetHeader("Accept")), "text/html") {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	c.JSON(http.StatusOK, gin.H{"logged_out": true})
}
