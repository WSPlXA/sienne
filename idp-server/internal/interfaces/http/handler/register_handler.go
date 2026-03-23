package handler

import (
	"errors"
	"net/http"

	"idp-server/internal/application/register"
	"idp-server/internal/interfaces/http/dto"

	"github.com/gin-gonic/gin"
)

type RegisterHandler struct {
	service register.Registrar
}

func NewRegisterHandler(service register.Registrar) *RegisterHandler {
	return &RegisterHandler{service: service}
}

func (h *RegisterHandler) Handle(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		c.JSON(http.StatusOK, gin.H{
			"endpoint": "register",
			"message":  "submit username, email, display_name and password to register",
		})
		return
	}

	var req dto.RegisterRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid register request"})
		return
	}

	result, err := h.service.Register(c.Request.Context(), register.RegisterInput{
		Username:      req.Username,
		Email:         req.Email,
		DisplayName:   req.DisplayName,
		Password:      req.Password,
		EmailVerified: req.EmailVerified,
		AutoActivate:  true,
	})
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, register.ErrUsernameAlreadyUsed), errors.Is(err, register.ErrEmailAlreadyUsed):
			status = http.StatusConflict
		case errors.Is(err, register.ErrInvalidUsername),
			errors.Is(err, register.ErrInvalidEmail),
			errors.Is(err, register.ErrInvalidDisplayName),
			errors.Is(err, register.ErrWeakPassword):
			status = http.StatusBadRequest
		default:
			status = http.StatusInternalServerError
		}

		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user_id":         result.UserID,
		"user_uuid":       result.UserUUID,
		"username":        result.Username,
		"email":           result.Email,
		"email_verified":  result.EmailVerified,
		"display_name":    result.DisplayName,
		"status":          result.Status,
		"created_at":      result.CreatedAt,
	})
}
