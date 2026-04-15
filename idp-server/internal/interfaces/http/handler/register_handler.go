package handler

import (
	"errors"
	"net/http"
	"strings"

	"idp-server/internal/application/register"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type RegisterHandler struct {
	service register.Registrar
}

type registerPageData struct {
	Username    string
	Email       string
	DisplayName string
	CSRFToken   string
	Error       string
	Success     bool
}

func NewRegisterHandler(service register.Registrar) *RegisterHandler {
	return &RegisterHandler{service: service}
}

func (h *RegisterHandler) Handle(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		csrfToken, err := ensureCSRFToken(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
			return
		}
		if wantsRegisterHTML(c.GetHeader("Accept")) {
			h.renderRegisterPage(c, http.StatusOK, registerPageData{
				CSRFToken: csrfToken,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"endpoint":   "register",
			"message":    "submit username, email, display_name and password to register",
			"csrf_token": csrfToken,
		})
		return
	}

	var req dto.RegisterRequest
	if err := c.ShouldBind(&req); err != nil {
		if wantsRegisterHTML(c.GetHeader("Accept")) {
			h.renderRegisterPage(c, http.StatusBadRequest, registerPageData{
				Username:    strings.TrimSpace(c.PostForm("username")),
				Email:       strings.TrimSpace(c.PostForm("email")),
				DisplayName: strings.TrimSpace(c.PostForm("display_name")),
				Error:       "Please check your input values.",
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid register request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		if wantsRegisterHTML(c.GetHeader("Accept")) {
			h.renderRegisterPage(c, http.StatusForbidden, registerPageData{
				Username:    req.Username,
				Email:       req.Email,
				DisplayName: req.DisplayName,
				Error:       errInvalidCSRFToken.Error(),
			})
			return
		}
		c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error()})
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
		var status int
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
		if wantsRegisterHTML(c.GetHeader("Accept")) {
			h.renderRegisterPage(c, status, registerPageData{
				Username:    req.Username,
				Email:       req.Email,
				DisplayName: req.DisplayName,
				Error:       err.Error(),
			})
			return
		}

		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	if wantsRegisterHTML(c.GetHeader("Accept")) {
		h.renderRegisterPage(c, http.StatusCreated, registerPageData{
			Success: true,
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user_id":        result.UserID,
		"user_uuid":      result.UserUUID,
		"username":       result.Username,
		"email":          result.Email,
		"email_verified": result.EmailVerified,
		"display_name":   result.DisplayName,
		"status":         result.Status,
		"created_at":     result.CreatedAt,
	})
}

func wantsRegisterHTML(accept string) bool {
	accept = strings.ToLower(strings.TrimSpace(accept))
	return strings.Contains(accept, "text/html")
}

func (h *RegisterHandler) renderRegisterPage(c *gin.Context, status int, data registerPageData) {
	if data.CSRFToken == "" {
		csrfToken, err := ensureCSRFToken(c)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
			return
		}
		data.CSRFToken = csrfToken
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = resource.RegisterPageTemplate.Execute(c.Writer, data)
}
