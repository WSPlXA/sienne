package handler

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	appclient "idp-server/internal/application/client"
	appsession "idp-server/internal/application/session"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

var errInvalidEndSessionRequest = errors.New("invalid end session request")

// EndSessionHandler 实现 OIDC RP-Initiated Logout 的浏览器交互。
// 它负责展示确认页、校验 post_logout_redirect_uri，并在退出后把用户送回 RP。
type EndSessionHandler struct {
	service           appsession.Manager
	redirectValidator appclient.LogoutRedirectValidator
}

type endSessionPageData struct {
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
	CSRFToken             string
	Error                 string
}

func NewEndSessionHandler(service appsession.Manager, redirectValidator appclient.LogoutRedirectValidator) *EndSessionHandler {
	return &EndSessionHandler{service: service, redirectValidator: redirectValidator}
}

func (h *EndSessionHandler) Get(c *gin.Context) {
	// GET 阶段只做请求校验和确认页展示，不真正执行登出。
	req := dto.EndSessionRequest{
		ClientID:              c.Query("client_id"),
		PostLogoutRedirectURI: c.Query("post_logout_redirect_uri"),
		State:                 c.Query("state"),
	}

	validatedRedirect, err := h.validateRedirect(c, req)
	if err != nil {
		log.Printf("end_session get_rejected ip=%s client_id=%q post_logout_redirect_uri=%q state_present=%t err=%v", c.ClientIP(), strings.TrimSpace(req.ClientID), strings.TrimSpace(req.PostLogoutRedirectURI), strings.TrimSpace(req.State) != "", err)
		h.writeRequestError(c, http.StatusBadRequest, req, err)
		return
	}

	csrfToken, err := ensureCSRFToken(c)
	if err != nil {
		log.Printf("end_session csrf_issue_failed method=GET ip=%s err=%v", c.ClientIP(), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
		return
	}
	log.Printf("end_session get_ready ip=%s client_id=%q post_logout_redirect_uri=%q state_present=%t", c.ClientIP(), strings.TrimSpace(req.ClientID), validatedRedirect, strings.TrimSpace(req.State) != "")

	if wantsHTML(c.GetHeader("Accept")) {
		h.renderPage(c, http.StatusOK, endSessionPageData{
			ClientID:              strings.TrimSpace(req.ClientID),
			PostLogoutRedirectURI: validatedRedirect,
			State:                 strings.TrimSpace(req.State),
			CSRFToken:             csrfToken,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"endpoint":                 "end_session",
		"action":                   "/connect/logout",
		"client_id":                strings.TrimSpace(req.ClientID),
		"post_logout_redirect_uri": strings.TrimSpace(req.PostLogoutRedirectURI),
		"state":                    strings.TrimSpace(req.State),
		"csrf_token":               csrfToken,
		"message":                  "submit POST /connect/logout from the browser context to end the IdP session",
	})
}

func (h *EndSessionHandler) Post(c *gin.Context) {
	// POST 阶段才真正结束本地会话，并按 OIDC 约定带着 state 回跳 RP。
	var req dto.EndSessionRequest
	if err := c.ShouldBind(&req); err != nil {
		log.Printf("end_session bind_failed method=POST ip=%s err=%v", c.ClientIP(), err)
		h.writeRequestError(c, http.StatusBadRequest, req, errInvalidEndSessionRequest)
		return
	}
	validatedRedirect, err := h.validateRedirect(c, req)
	if err != nil {
		log.Printf("end_session post_rejected ip=%s client_id=%q post_logout_redirect_uri=%q state_present=%t err=%v", c.ClientIP(), strings.TrimSpace(req.ClientID), strings.TrimSpace(req.PostLogoutRedirectURI), strings.TrimSpace(req.State) != "", err)
		h.writeRequestError(c, http.StatusBadRequest, req, err)
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		log.Printf("end_session csrf_validation_failed method=POST ip=%s client_id=%q", c.ClientIP(), strings.TrimSpace(req.ClientID))
		if wantsHTML(c.GetHeader("Accept")) {
			h.renderPage(c, http.StatusForbidden, endSessionPageData{
				ClientID:              strings.TrimSpace(req.ClientID),
				PostLogoutRedirectURI: validatedRedirect,
				State:                 strings.TrimSpace(req.State),
				Error:                 errInvalidCSRFToken.Error(),
			})
			return
		}
		writeCSRFError(c)
		return
	}

	sessionID, _ := c.Cookie("idp_session")
	if h.service != nil {
		if _, err := h.service.Logout(c.Request.Context(), appsession.LogoutInput{SessionID: sessionID}); err != nil {
			log.Printf("end_session logout_failed ip=%s client_id=%q session_present=%t err=%v", c.ClientIP(), strings.TrimSpace(req.ClientID), sessionID != "", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
			return
		}
	}

	// IdP 本地会话失效后，浏览器 cookie 也立即清除。
	c.SetCookie("idp_session", "", -1, "/", "", true, true)

	if validatedRedirect != "" {
		redirectTarget := buildPostLogoutRedirect(validatedRedirect, strings.TrimSpace(req.State))
		log.Printf("end_session logout_succeeded ip=%s client_id=%q session_present=%t redirect_uri=%q", c.ClientIP(), strings.TrimSpace(req.ClientID), sessionID != "", redirectTarget)
		c.Redirect(http.StatusFound, redirectTarget)
		return
	}

	if wantsHTML(c.GetHeader("Accept")) {
		log.Printf("end_session logout_succeeded ip=%s client_id=%q session_present=%t redirect_uri=%q", c.ClientIP(), strings.TrimSpace(req.ClientID), sessionID != "", "/login")
		c.Redirect(http.StatusFound, "/login")
		return
	}

	log.Printf("end_session logout_succeeded ip=%s client_id=%q session_present=%t redirect_uri=%q", c.ClientIP(), strings.TrimSpace(req.ClientID), sessionID != "", "")
	c.JSON(http.StatusOK, gin.H{"logged_out": true})
}

func (h *EndSessionHandler) validateRedirect(c *gin.Context, req dto.EndSessionRequest) (string, error) {
	// OIDC end-session 里 post_logout_redirect_uri 不能直接信任用户输入，
	// 必须结合 client_id 回查该客户端已注册的合法退出回调地址。
	clientID := strings.TrimSpace(req.ClientID)
	redirectURI := strings.TrimSpace(req.PostLogoutRedirectURI)
	state := strings.TrimSpace(req.State)

	if redirectURI == "" {
		if clientID != "" || state != "" {
			return "", errInvalidEndSessionRequest
		}
		return "", nil
	}
	if clientID == "" || h.redirectValidator == nil {
		return "", errInvalidEndSessionRequest
	}

	result, err := h.redirectValidator.ValidatePostLogoutRedirectURI(c.Request.Context(), appclient.ValidatePostLogoutRedirectURIInput{
		ClientID:    clientID,
		RedirectURI: redirectURI,
	})
	if err != nil {
		return "", err
	}
	if result == nil {
		return "", errInvalidEndSessionRequest
	}
	return result.RedirectURI, nil
}

func (h *EndSessionHandler) writeRequestError(c *gin.Context, status int, req dto.EndSessionRequest, err error) {
	// 浏览器拿友好页面，API/脚本调用拿 JSON 错误。
	if wantsHTML(c.GetHeader("Accept")) {
		h.renderPage(c, status, endSessionPageData{
			ClientID:              strings.TrimSpace(req.ClientID),
			PostLogoutRedirectURI: strings.TrimSpace(req.PostLogoutRedirectURI),
			State:                 strings.TrimSpace(req.State),
			Error:                 endSessionErrorMessage(err),
		})
		return
	}
	c.JSON(status, gin.H{"error": endSessionErrorMessage(err)})
}

func (h *EndSessionHandler) renderPage(c *gin.Context, status int, data endSessionPageData) {
	// 渲染确认页前兜底补一个 CSRF token，确保退出动作必须经由真实表单提交。
	if data.CSRFToken == "" {
		csrfToken, err := ensureCSRFToken(c)
		if err != nil {
			log.Printf("end_session render_failed ip=%s err=%v", c.ClientIP(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
			return
		}
		data.CSRFToken = csrfToken
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = resource.LogoutPageTemplate.Execute(c.Writer, data)
}

func endSessionErrorMessage(err error) string {
	// 对浏览器暴露的错误文案比内部错误更收敛，避免泄露过多校验细节。
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errInvalidEndSessionRequest):
		return errInvalidEndSessionRequest.Error()
	case errors.Is(err, appclient.ErrInvalidRedirectURI), errors.Is(err, appclient.ErrClientNotFound):
		return "invalid post_logout_redirect_uri"
	default:
		return "logout request rejected"
	}
}

func buildPostLogoutRedirect(redirectURI, state string) string {
	// OIDC 允许把 state 原样带回 RP，便于调用方把这次登出请求和本地状态对上。
	if strings.TrimSpace(state) == "" {
		return redirectURI
	}

	parsed, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	query := parsed.Query()
	query.Set("state", state)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
