package handler

import (
	"errors"
	"log"
	"net/http"
	"time"

	"idp-server/internal/application/authn"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/internal/ports/repository"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type LoginHandler struct {
	authnService         authn.Authenticator
	federatedOIDCEnabled bool
	auditRepo            repository.AuditEventRepository
}

type loginPageData struct {
	Username             string
	ReturnTo             string
	CSRFToken            string
	Error                string
	Success              bool
	FederatedOIDCEnabled bool
}

func NewLoginHandler(authnService authn.Authenticator, federatedOIDCEnabled bool, auditRepo ...repository.AuditEventRepository) *LoginHandler {
	var repo repository.AuditEventRepository
	if len(auditRepo) > 0 {
		repo = auditRepo[0]
	}
	return &LoginHandler{
		authnService:         authnService,
		federatedOIDCEnabled: federatedOIDCEnabled,
		auditRepo:            repo,
	}
}

func (h *LoginHandler) Handle(c *gin.Context) {
	// LoginHandler 同时服务浏览器表单和 API/脚本调用：
	// GET 负责展示页面或启动联邦登录，
	// POST 负责校验 CSRF 后真正执行认证。
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
			// 某些登录方式（例如联邦 OIDC 回调）会把 code/state 带回 GET 请求，
			// 这里直接进入认证编排，而不是单纯渲染登录页。
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

	// POST 分支处理表单提交：先做输入绑定、return_to 校验和 CSRF 校验，
	// 通过后再把请求交给应用层认证服务。
	var req dto.LoginRequest
	if err := c.ShouldBind(&req); err != nil {
		log.Printf("login bind_failed method=%s ip=%s err=%v", c.Request.Method, c.ClientIP(), err)
		if wantsHTML(c.GetHeader("Accept")) {
			h.renderLoginPage(c, http.StatusBadRequest, loginPageData{
				Username:             c.PostForm("username"),
				ReturnTo:             c.PostForm("return_to"),
				Error:                "Please enter both username and password.",
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
	// handleAuthenticate 是真正的桥接点：
	// 把 HTTP 请求转换成 AuthenticateInput，再把应用层结果翻译回 cookie、跳转或 JSON。
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
		case errors.Is(err, authn.ErrMFARequired):
			status = http.StatusUnauthorized
		case errors.Is(err, authn.ErrMFAEnrollmentRequired):
			status = http.StatusForbidden
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

		if errors.Is(err, authn.ErrMFAEnrollmentRequired) && result != nil && result.SessionID != "" {
			// “要求补绑 MFA” 与“登录失败”不同：
			// 用户第一要素已经通过，所以会先发会话，再把前端导向绑定页面。
			maxAge := int(time.Until(result.ExpiresAt).Seconds())
			c.SetCookie("idp_session", result.SessionID, maxAge, "/", "", true, true)
			setupURI := buildMFASetupURI(req.ReturnTo)
			if wantsHTML(c.GetHeader("Accept")) {
				c.Redirect(http.StatusFound, setupURI)
				return
			}
			c.JSON(status, gin.H{
				"error":                   err.Error(),
				"mfa_enrollment_required": true,
				"redirect_uri":            setupURI,
				"return_to":               req.ReturnTo,
			})
			return
		}

		if errors.Is(err, authn.ErrMFARequired) && result != nil && result.MFAChallengeID != "" {
			// MFA 挑战 ID 单独放在短时 cookie 中，让后续 TOTP / Passkey 页能继续这次挑战。
			c.SetCookie(mfaChallengeCookieName, result.MFAChallengeID, 300, "/", "", true, true)
			if wantsHTML(c.GetHeader("Accept")) {
				c.Redirect(http.StatusFound, "/login/totp")
				return
			}
			c.JSON(status, gin.H{
				"error":             err.Error(),
				"mfa_required":      true,
				"challenge_id":      result.MFAChallengeID,
				"mfa_mode":          result.MFAMode,
				"passkey_available": result.PasskeyAvailable,
				"push_status":       result.PushStatus,
				"push_code":         result.PushCode,
				"redirect_uri":      "/login/totp",
				"return_to":         req.ReturnTo,
			})
			return
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
		// 联邦登录第一跳的典型返回：没有本地 session，只有一个需要浏览器继续前往的上游地址。
		log.Printf("login federated_redirect ip=%s redirect_uri=%q", c.ClientIP(), result.RedirectURI)
		c.Redirect(http.StatusFound, result.RedirectURI)
		return
	}

	// 本地登录完成后，最终跳转地址优先级通常是：
	// return_to > 应用层指定 redirect > 基于角色的默认页面。
	redirectURI := resolveBrowserPostLoginRedirect(req.ReturnTo, result.RedirectURI, result.RoleCode)
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
	// session cookie 设置为 HttpOnly，减少前端脚本直接读取会话标识的机会。
	c.SetCookie("idp_session", result.SessionID, maxAge, "/", "", true, true)
	recordLoginSuccessAuditEvent(c.Request.Context(), h.auditRepo, c, result.UserID, result.Subject, result.RoleCode, req.Method, redirectURI)
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

func buildMFASetupURI(returnTo string) string {
	// 绑定 MFA 后往往还要回到原始业务页面，所以这里也沿用 return_to 传递上下文。
	if returnTo == "" {
		return "/mfa/passkey/setup"
	}
	return withReturnTo("/mfa/passkey/setup", returnTo)
}

func shouldProcessLoginGET(req dto.LoginRequest) bool {
	// GET 只在明显带有上游回调参数时才进入认证流程，
	// 避免普通打开登录页时误触发认证逻辑。
	return req.Code != "" || req.State != ""
}

func localizeLoginError(err error) string {
	// HTML 页面面向终端用户，所以这里用更友好的文案替代内部错误码。
	switch {
	case errors.Is(err, authn.ErrInvalidCredentials):
		return "Invalid username or password."
	case errors.Is(err, authn.ErrUserLocked):
		return "Your account is locked."
	case errors.Is(err, authn.ErrUserDisabled):
		return "Your account is disabled."
	case errors.Is(err, authn.ErrRateLimited):
		return "Too many attempts. Please try again later."
	case errors.Is(err, authn.ErrUnsupportedMethod):
		return "This authentication method is currently unavailable."
	default:
		return "Sign-in failed."
	}
}

func (h *LoginHandler) writeInvalidReturnTo(c *gin.Context) {
	// return_to 只允许站内跳转，避免把登录流程变成开放重定向入口。
	if wantsHTML(c.GetHeader("Accept")) {
		h.renderLoginPage(c, http.StatusBadRequest, loginPageData{
			Error:                "Invalid redirect target.",
			FederatedOIDCEnabled: h.federatedOIDCEnabled,
		})
		return
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidLocalRedirectTarget.Error()})
}

func (h *LoginHandler) writeInvalidCSRF(c *gin.Context, req dto.LoginRequest) {
	// CSRF 失败时尽量保留用户名和 return_to，减少用户重新输入的成本。
	if wantsHTML(c.GetHeader("Accept")) {
		h.renderLoginPage(c, http.StatusForbidden, loginPageData{
			Username:             req.Username,
			ReturnTo:             req.ReturnTo,
			Error:                "CSRF validation failed.",
			FederatedOIDCEnabled: h.federatedOIDCEnabled,
		})
		return
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error()})
}

func (h *LoginHandler) renderLoginPage(c *gin.Context, status int, data loginPageData) {
	// 渲染前兜底补一个 CSRF token，确保无论从哪个分支进入页面都能提交表单。
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
