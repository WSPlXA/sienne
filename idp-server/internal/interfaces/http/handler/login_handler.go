package handler

import (
	"errors"
	"log"
	"net/http"
	"time"

	"idp-server/internal/application/authn"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type LoginHandler struct {
	authnService         authn.Authenticator
	federatedOIDCEnabled bool
}

type loginPageData struct {
	Username             string
	ReturnTo             string
	CSRFToken            string
	Error                string
	Success              bool
	FederatedOIDCEnabled bool
}

func NewLoginHandler(authnService authn.Authenticator, federatedOIDCEnabled bool) *LoginHandler {
	return &LoginHandler{
		authnService:         authnService,
		federatedOIDCEnabled: federatedOIDCEnabled,
	}
}

func (h *LoginHandler) Handle(c *gin.Context) {
	if c.Request.Method == http.MethodGet {
		req := dto.LoginRequest{
			Method:      c.Query("method"),
			ReturnTo:    c.Query("return_to"),
			RedirectURI: c.Query("redirect_uri"),
			State:       c.Query("state"),
			Code:        c.Query("code"),
			Nonce:       c.Query("nonce"),
		}
		validatedReturnTo, err := validateLocalRedirectTarget(req.ReturnTo)
		if err != nil {
			log.Printf("login invalid_return_to method=GET ip=%s return_to=%q", c.ClientIP(), req.ReturnTo)
			h.writeInvalidReturnTo(c)
			return
		}
		req.ReturnTo = validatedReturnTo
		if shouldProcessLoginGET(req) {
			h.handleAuthenticate(c, req)
			return
		}

		csrfToken, err := ensureCSRFToken(c)
		if err != nil {
			log.Printf("login csrf_issue_failed method=GET ip=%s err=%v", c.ClientIP(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
			return
		}

		if wantsHTML(c.GetHeader("Accept")) {
			h.renderLoginPage(c, http.StatusOK, loginPageData{
				CSRFToken:            csrfToken,
				ReturnTo:             req.ReturnTo,
				FederatedOIDCEnabled: h.federatedOIDCEnabled,
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"endpoint":                "login",
			"message":                 "submit username and password to login",
			"csrf_token":              csrfToken,
			"return_to":               req.ReturnTo,
			"federated_oidc_enabled":  h.federatedOIDCEnabled,
			"federated_oidc_endpoint": "/login",
			"federated_oidc_method":   http.MethodPost,
		})
		return
	}

	var req dto.LoginRequest
	if err := c.ShouldBind(&req); err != nil {
		log.Printf("login bind_failed method=%s ip=%s err=%v", c.Request.Method, c.ClientIP(), err)
		if wantsHTML(c.GetHeader("Accept")) {
			h.renderLoginPage(c, http.StatusBadRequest, loginPageData{
				Username:             c.PostForm("username"),
				ReturnTo:             c.PostForm("return_to"),
				Error:                "ユーザー名とパスワードを入力してください。",
				FederatedOIDCEnabled: h.federatedOIDCEnabled,
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid login request"})
		return
	}

	validatedReturnTo, err := validateLocalRedirectTarget(req.ReturnTo)
	if err != nil {
		log.Printf("login invalid_return_to method=POST ip=%s username=%q return_to=%q", c.ClientIP(), req.Username, req.ReturnTo)
		h.writeInvalidReturnTo(c)
		return
	}
	req.ReturnTo = validatedReturnTo
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		log.Printf("login csrf_validation_failed method=POST ip=%s username=%q", c.ClientIP(), req.Username)
		h.writeInvalidCSRF(c, req)
		return
	}

	h.handleAuthenticate(c, req)
}

func (h *LoginHandler) handleAuthenticate(c *gin.Context, req dto.LoginRequest) {
	result, err := h.authnService.Authenticate(c.Request.Context(), authn.AuthenticateInput{
		Method:      req.Method,
		Username:    req.Username,
		Password:    req.Password,
		RedirectURI: req.RedirectURI,
		ReturnTo:    req.ReturnTo,
		State:       req.State,
		Code:        req.Code,
		Nonce:       req.Nonce,
		IPAddress:   c.ClientIP(),
		UserAgent:   c.GetHeader("User-Agent"),
	})
	if err != nil {
		log.Printf("login authenticate_failed method=%q ip=%s username=%q err=%v", req.Method, c.ClientIP(), req.Username, err)
		status := http.StatusUnauthorized
		switch {
		case errors.Is(err, authn.ErrUnsupportedMethod):
			status = http.StatusBadRequest
		case errors.Is(err, authn.ErrRateLimited):
			status = http.StatusTooManyRequests
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
				Username:             req.Username,
				ReturnTo:             req.ReturnTo,
				Error:                localizeLoginError(err),
				FederatedOIDCEnabled: h.federatedOIDCEnabled,
			})
			return
		}

		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	if result != nil && result.SessionID == "" && result.RedirectURI != "" {
		log.Printf("login federated_redirect ip=%s redirect_uri=%q", c.ClientIP(), result.RedirectURI)
		c.Redirect(http.StatusFound, result.RedirectURI)
		return
	}

	redirectURI := req.ReturnTo
	if redirectURI == "" {
		redirectURI = result.RedirectURI
	}
	redirectURI, err = validateLocalRedirectTarget(redirectURI)
	if err != nil {
		log.Printf("login invalid_redirect_after_auth ip=%s username=%q redirect_uri=%q", c.ClientIP(), req.Username, redirectURI)
		h.writeInvalidReturnTo(c)
		return
	}
	if _, err := ensureCSRFToken(c); err != nil {
		log.Printf("login csrf_issue_failed method=POST ip=%s username=%q err=%v", c.ClientIP(), req.Username, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
		return
	}
	maxAge := int(time.Until(result.ExpiresAt).Seconds())
	c.SetCookie("idp_session", result.SessionID, maxAge, "/", "", false, true)
	log.Printf("login authenticate_succeeded method=%q ip=%s username=%q user_id=%d redirect_uri=%q", req.Method, c.ClientIP(), req.Username, result.UserID, redirectURI)
	if redirectURI != "" {
		c.Redirect(http.StatusFound, redirectURI)
		return
	}
	if wantsHTML(c.GetHeader("Accept")) {
		h.renderLoginPage(c, http.StatusOK, loginPageData{
			Username:             req.Username,
			Success:              true,
			FederatedOIDCEnabled: h.federatedOIDCEnabled,
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

func shouldProcessLoginGET(req dto.LoginRequest) bool {
	return req.Code != "" || req.State != ""
}

func localizeLoginError(err error) string {
	switch {
	case errors.Is(err, authn.ErrInvalidCredentials):
		return "ユーザー名またはパスワードが正しくありません。"
	case errors.Is(err, authn.ErrUserLocked):
		return "アカウントはロックされています。"
	case errors.Is(err, authn.ErrUserDisabled):
		return "アカウントは無効化されています。"
	case errors.Is(err, authn.ErrRateLimited):
		return "試行回数が多すぎます。しばらく待ってから再試行してください。"
	case errors.Is(err, authn.ErrUnsupportedMethod):
		return "この認証方式は現在利用できません。"
	default:
		return "ログイン処理に失敗しました。"
	}
}

func (h *LoginHandler) writeInvalidReturnTo(c *gin.Context) {
	if wantsHTML(c.GetHeader("Accept")) {
		h.renderLoginPage(c, http.StatusBadRequest, loginPageData{
			Error:                "遷移先が不正です。",
			FederatedOIDCEnabled: h.federatedOIDCEnabled,
		})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidLocalRedirectTarget.Error()})
}

func (h *LoginHandler) writeInvalidCSRF(c *gin.Context, req dto.LoginRequest) {
	if wantsHTML(c.GetHeader("Accept")) {
		h.renderLoginPage(c, http.StatusForbidden, loginPageData{
			Username:             req.Username,
			ReturnTo:             req.ReturnTo,
			Error:                "リクエストの整合性検証に失敗しました。",
			FederatedOIDCEnabled: h.federatedOIDCEnabled,
		})
		return
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error()})
}

func (h *LoginHandler) renderLoginPage(c *gin.Context, status int, data loginPageData) {
	if data.CSRFToken == "" {
		csrfToken, err := ensureCSRFToken(c)
		if err != nil {
			log.Printf("login render_failed ip=%s err=%v", c.ClientIP(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
			return
		}
		data.CSRFToken = csrfToken
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = resource.LoginPageTemplate.Execute(c.Writer, data)
}
