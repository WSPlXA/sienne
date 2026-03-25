package handler

import (
	"errors"
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
	req := dto.EndSessionRequest{
		ClientID:              c.Query("client_id"),
		PostLogoutRedirectURI: c.Query("post_logout_redirect_uri"),
		State:                 c.Query("state"),
	}

	if _, err := h.validateRedirect(c, req); err != nil {
		h.writeRequestError(c, http.StatusBadRequest, req, err)
		return
	}

	csrfToken, err := ensureCSRFToken(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate csrf token"})
		return
	}

	if wantsHTML(c.GetHeader("Accept")) {
		h.renderPage(c, http.StatusOK, endSessionPageData{
			ClientID:              strings.TrimSpace(req.ClientID),
			PostLogoutRedirectURI: strings.TrimSpace(req.PostLogoutRedirectURI),
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
	var req dto.EndSessionRequest
	if err := c.ShouldBind(&req); err != nil {
		h.writeRequestError(c, http.StatusBadRequest, req, errInvalidEndSessionRequest)
		return
	}
	validatedRedirect, err := h.validateRedirect(c, req)
	if err != nil {
		h.writeRequestError(c, http.StatusBadRequest, req, err)
		return
	}
	if err := validateCSRFToken(c, req.CSRFToken); err != nil {
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
			return
		}
	}

	c.SetCookie("idp_session", "", -1, "/", "", false, true)

	if validatedRedirect != "" {
		c.Redirect(http.StatusFound, buildPostLogoutRedirect(validatedRedirect, strings.TrimSpace(req.State)))
		return
	}

	if wantsHTML(c.GetHeader("Accept")) {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	c.JSON(http.StatusOK, gin.H{"logged_out": true})
}

func (h *EndSessionHandler) validateRedirect(c *gin.Context, req dto.EndSessionRequest) (string, error) {
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
	_ = resource.LogoutPageTemplate.Execute(c.Writer, data)
}

func endSessionErrorMessage(err error) string {
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
