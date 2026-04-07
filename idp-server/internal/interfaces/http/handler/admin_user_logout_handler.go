package handler

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	appsession "idp-server/internal/application/session"
	"idp-server/internal/interfaces/http/dto"
)

type AdminUserLogoutHandler struct {
	service appsession.Manager
}

func NewAdminUserLogoutHandler(service appsession.Manager) *AdminUserLogoutHandler {
	return &AdminUserLogoutHandler{service: service}
}

func (h *AdminUserLogoutHandler) Handle(c *gin.Context) {
	var req dto.LogoutRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid logout request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		writeCSRFError(c)
		return
	}

	userID, err := strconv.ParseInt(strings.TrimSpace(c.Param("user_id")), 10, 64)
	if err != nil || userID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	result, err := h.service.AdminLogoutUser(c.Request.Context(), appsession.AdminLogoutUserInput{
		UserID: userID,
	})
	if err != nil {
		log.Printf("admin_user_logout failed ip=%s target_user_id=%d err=%v", c.ClientIP(), userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "logout user failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logged_out_user":        true,
		"user_id":                result.UserID,
		"revoked_session_count":  result.RevokedSessionCount,
		"revoked_access_tokens":  result.RevokedAccessTokens,
		"revoked_refresh_tokens": result.RevokedRefreshTokens,
	})
}
