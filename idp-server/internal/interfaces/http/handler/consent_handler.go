package handler

import (
	"errors"
	"log"
	"net/http"
	"strings"

	appconsent "idp-server/internal/application/consent"
	"idp-server/internal/interfaces/http/dto"
	"idp-server/resource"

	"github.com/gin-gonic/gin"
)

type ConsentHandler struct {
	service appconsent.Manager
}

type consentPageData struct {
	ClientID   string
	ClientName string
	Scopes     []string
	ReturnTo   string
	CSRFToken  string
	Error      string
}

func NewConsentHandler(service appconsent.Manager) *ConsentHandler {
	return &ConsentHandler{service: service}
}

func (h *ConsentHandler) Handle(c *gin.Context) {
	// ConsentHandler 负责 OAuth2/OIDC 授权流程中的用户确认页。
	// 它依赖已有登录态，从 return_to 中还原原始 authorize 请求，再决定展示或提交用户决策。
	sessionID, _ := c.Cookie("idp_session")

	if c.Request.Method == http.MethodGet {
		returnTo := c.Query("return_to")
		// Prepare 只做“展示前准备”：解析 client、scope 和回跳地址，
		// 不在这个阶段真正记录 consent。
		result, err := h.service.Prepare(c.Request.Context(), appconsent.PrepareInput{
			ReturnTo:  returnTo,
			SessionID: sessionID,
		})
		if err != nil {
			log.Printf("consent prepare_failed ip=%s session_present=%t return_to=%q err=%v", c.ClientIP(), sessionID != "", returnTo, err)
			h.writeError(c, err, returnTo)
			return
		}

		csrfToken, err := ensureCSRFToken(c)
		if err != nil {
			log.Printf("consent csrf_issue_failed ip=%s session_present=%t err=%v", c.ClientIP(), sessionID != "", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
			return
		}
		log.Printf("consent prepare_succeeded ip=%s session_present=%t client_id=%q scopes=%d", c.ClientIP(), sessionID != "", result.ClientID, len(result.Scopes))

		if wantsHTML(c.GetHeader("Accept")) {
			h.renderConsentPage(c, http.StatusOK, consentPageData{
				ClientID:   result.ClientID,
				ClientName: result.ClientName,
				Scopes:     result.Scopes,
				ReturnTo:   result.ReturnTo,
				CSRFToken:  csrfToken,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"endpoint":    "consent",
			"client_id":   result.ClientID,
			"client_name": result.ClientName,
			"scopes":      result.Scopes,
			"csrf_token":  csrfToken,
			"return_to":   result.ReturnTo,
			"message":     "submit action=accept or action=deny",
		})
		return
	}

	// POST 分支真正提交“允许 / 拒绝”决策，并再次校验 CSRF。
	var req dto.ConsentDecisionRequest
	if err := c.ShouldBind(&req); err != nil {
		log.Printf("consent bind_failed ip=%s session_present=%t err=%v", c.ClientIP(), sessionID != "", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid consent request"})
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
		log.Printf("consent csrf_validation_failed ip=%s session_present=%t action=%q return_to=%q", c.ClientIP(), sessionID != "", req.Action, req.ReturnTo)
		h.writeCSRFFailure(c, req.ReturnTo, sessionID)
		return
	}

	result, err := h.service.Decide(c.Request.Context(), appconsent.DecideInput{
		ReturnTo:  req.ReturnTo,
		SessionID: sessionID,
		Action:    req.Action,
	})
	if err != nil {
		log.Printf("consent decide_failed ip=%s session_present=%t action=%q return_to=%q err=%v", c.ClientIP(), sessionID != "", req.Action, req.ReturnTo, err)
		h.writeError(c, err, req.ReturnTo)
		return
	}

	log.Printf("consent decide_succeeded ip=%s session_present=%t action=%q redirect_uri=%q", c.ClientIP(), sessionID != "", req.Action, result.RedirectURI)
	c.Redirect(http.StatusFound, result.RedirectURI)
}

func wantsHTML(accept string) bool {
	// consent 页同样兼顾浏览器和非浏览器调用方，因此用 Accept 头判断返回 HTML 还是 JSON。
	accept = strings.ToLower(accept)
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

func (h *ConsentHandler) renderConsentPage(c *gin.Context, status int, data consentPageData) {
	// 渲染兜底补 token，避免错误页/重试页缺少可提交的 CSRF 字段。
	if data.CSRFToken == "" {
		csrfToken, err := ensureCSRFToken(c)
		if err != nil {
			log.Printf("consent render_failed ip=%s err=%v", c.ClientIP(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
			return
		}
		data.CSRFToken = csrfToken
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)
	_ = resource.ConsentPageTemplate.Execute(c.Writer, data)
}

func (h *ConsentHandler) writeError(c *gin.Context, err error, returnTo string) {
	// 这里区分“需要重新登录”“请求本身有问题”“服务端内部异常”三类错误，
	// 让浏览器流和 API 流都能得到更合理的反馈。
	switch {
	case errors.Is(err, appconsent.ErrLoginRequired):
		redirectTo := withReturnTo("/login", c.Request.URL.RequestURI())
		c.Redirect(http.StatusFound, redirectTo)
	case errors.Is(err, appconsent.ErrInvalidReturnTo),
		errors.Is(err, appconsent.ErrInvalidClient),
		errors.Is(err, appconsent.ErrInvalidScope),
		errors.Is(err, appconsent.ErrInvalidAction):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "return_to": returnTo})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "consent processing failed"})
	}
}

func (h *ConsentHandler) writeCSRFFailure(c *gin.Context, returnTo, sessionID string) {
	// CSRF 失败时重新拉一遍展示数据，这样用户看到的页面上下文不会丢失。
	if wantsHTML(c.GetHeader("Accept")) {
		data := consentPageData{
			ReturnTo: returnTo,
			Error:    "CSRF validation failed.",
		}
		if h.service != nil {
			result, err := h.service.Prepare(c.Request.Context(), appconsent.PrepareInput{
				ReturnTo:  returnTo,
				SessionID: sessionID,
			})
			if err == nil && result != nil {
				data.ClientID = result.ClientID
				data.ClientName = result.ClientName
				data.Scopes = result.Scopes
				data.ReturnTo = result.ReturnTo
			}
		}
		h.renderConsentPage(c, http.StatusForbidden, data)
		return
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error(), "return_to": returnTo})
}
