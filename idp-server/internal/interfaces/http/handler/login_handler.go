package handler

import (
	"errors"
	"net/http"
	"time"

	"idp-server/internal/application/authn"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type LoginHandler struct {
	authnService authn.Authenticator
}

type loginPageData struct {
	Username string
	ReturnTo string
	Error    string
	Success  bool
}

func NewLoginHandler(authnService authn.Authenticator) *LoginHandler {
	return &LoginHandler{authnService: authnService}
}

func (h *LoginHandler) Handle(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		if wantsHTML(c.GetHeader("Accept")) {
			h.renderLoginPage(c, http.StatusOK, loginPageData{
				ReturnTo: c.Query("return_to"),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"endpoint":  "login",
			"message":   "submit username and password to login",
			"return_to": c.Query("return_to"),
		})
		return
	}

	var req dto.LoginRequest
	if err := c.ShouldBind(&req); err != nil {
		if wantsHTML(c.GetHeader("Accept")) {
			h.renderLoginPage(c, http.StatusBadRequest, loginPageData{
				Username: c.PostForm("username"),
				ReturnTo: c.PostForm("return_to"),
				Error:    "please enter both username and password",
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid login request"})
		return
	}

	result, err := h.authnService.Authenticate(c.Request.Context(), authn.AuthenticateInput{
		Username:  req.Username,
		Password:  req.Password,
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
	})
	if err != nil {
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, authn.ErrUserLocked):
			status = http.StatusLocked
		case errors.Is(err, authn.ErrUserDisabled):
			status = http.StatusForbidden
		case errors.Is(err, authn.ErrInvalidCredentials):
			status = http.StatusUnauthorized
		default:
			status = http.StatusInternalServerError
		}

		if wantsHTML(c.GetHeader("Accept")) {
			h.renderLoginPage(c, status, loginPageData{
				Username: req.Username,
				ReturnTo: req.ReturnTo,
				Error:    err.Error(),
			})
			return
		}

		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	maxAge := int(time.Until(result.ExpiresAt).Seconds())
	c.SetCookie("idp_session", result.SessionID, maxAge, "/", "", false, true)
	if req.ReturnTo != "" {
		c.Redirect(http.StatusFound, req.ReturnTo)
		return
	}
	if wantsHTML(c.GetHeader("Accept")) {
		h.renderLoginPage(c, http.StatusOK, loginPageData{
			Username: req.Username,
			Success:  true,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"session_id": result.SessionID,
		"user_id":    result.UserID,
		"subject":    result.Subject,
		"expires_at": result.ExpiresAt,
	})
}

func (h *LoginHandler) renderLoginPage(c *gin.Context, status int, data loginPageData) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = resource.LoginPageTemplate.Execute(c.Writer, data)
}
