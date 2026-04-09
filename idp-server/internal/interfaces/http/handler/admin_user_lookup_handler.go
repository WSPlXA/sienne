package handler

import (
	"net/http"
	"strings"

	"idp-server/internal/ports/repository"

	"github.com/gin-gonic/gin"
)

type AdminUserLookupHandler struct {
	users repository.UserRepository
}

func NewAdminUserLookupHandler(users repository.UserRepository) *AdminUserLookupHandler {
	return &AdminUserLookupHandler{users: users}
}

func (h *AdminUserLookupHandler) LookupByUsername(c *gin.Context) {
	username := strings.TrimSpace(c.Query("username"))
	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}
	if h.users == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user lookup service unavailable"})
		return
	}
	userModel, err := h.users.FindByUsername(c.Request.Context(), username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to lookup user"})
		return
	}
	if userModel == nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":    "user not found",
			"username": username,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"user_id":        userModel.ID,
		"user_uuid":      userModel.UserUUID,
		"username":       userModel.Username,
		"email":          userModel.Email,
		"display_name":   userModel.DisplayName,
		"status":         userModel.Status,
		"role_code":      userModel.RoleCode,
		"privilege_mask": userModel.PrivilegeMask,
		"tenant_scope":   userModel.TenantScope,
	})
}
