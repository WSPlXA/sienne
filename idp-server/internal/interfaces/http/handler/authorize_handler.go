package handler

import (
	"errors"
	"idp-server/internal/application/authz"
	appauthz "idp-server/internal/application/authz"
	"idp-server/internal/interfaces/http/dto"
	pkgoauth2 "idp-server/pkg/oauth2"
	"net/http"
	"net/url"
)

type AuthorizationHandler struct {
	authzService authz.Service
}

func NewAuthorizationHandler(authzService authz.Service) *AuthorizationHandler {
	return &AuthorizationHandler{
		authzService: authzService,
	}
}

func (h *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// authorize handler 负责把浏览器请求翻译成应用层命令，
	// 再根据 Authorize 的结果决定跳去登录、跳去 consent，还是直接回调 client。
	ctx := r.Context()
	req := dto.AuthorizeRequest{
		ResponseType:        r.URL.Query().Get("response_type"),
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		Nonce:               r.URL.Query().Get("nonce"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
	}

	sessionID := ""
	if cookie, err := r.Cookie("idp_session"); err == nil {
		// /oauth2/authorize 依赖浏览器已有的登录会话 cookie 来判断用户身份。
		sessionID = cookie.Value
	}

	cmd := &appauthz.AuthorizationCommand{
		SessionID:           sessionID,
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.ScopeList(),
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	}

	result, err := h.authzService.Authorize(ctx, cmd)
	if err != nil {
		h.writeAuthorizeError(w, r, cmd, err)
		return
	}
	if result.RequireConsent {
		// 把当前 authorize 请求原样带进 return_to，保证 consent 完成后能回到原始请求。
		http.Redirect(w, r, withReturnTo(result.ConsentRedirectURI, r.URL.RequestURI()), http.StatusFound)
		return
	}
	if result.RequireLogin {
		// 未登录时同样保留原始请求，登录成功后继续走授权流程而不是回首页。
		http.Redirect(w, r, withReturnTo(result.LoginRedirectURI, r.URL.RequestURI()), http.StatusFound)
		return
	}
	redirectURL, err := buildAuthorizeSuccessRedirect(result.RedirectURI, result.Code, result.State)
	if err != nil {
		http.Error(w, "failed to build redirect url", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)

}
func buildAuthorizeSuccessRedirect(redirectURI, code, state string) (string, error) {
	// 授权成功时按 OAuth2 规范把 code/state 放回 redirect_uri 的查询参数里。
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (h *AuthorizationHandler) writeAuthorizeError(
	w http.ResponseWriter,
	r *http.Request,
	cmd *appauthz.AuthorizationCommand,
	err error,
) {
	// 这里把领域错误映射成 OAuth2 标准错误码，
	// 方便客户端 SDK 依据规范处理失败场景。
	oauthErr := pkgoauth2.Error{
		Code:        "invalid_request",
		Description: err.Error(),
	}

	switch {
	case errors.Is(err, appauthz.ErrUnsupportedResponseType):
		oauthErr.Code = "unsupported_response_type"
	case errors.Is(err, appauthz.ErrInvalidScope):
		oauthErr.Code = "invalid_scope"
	case errors.Is(err, appauthz.ErrInvalidClient):
		oauthErr.Code = "unauthorized_client"
	case errors.Is(err, appauthz.ErrInvalidRedirectURI),
		errors.Is(err, appauthz.ErrInvalidCodeChallenge),
		errors.Is(err, appauthz.ErrInvalidRequest):
		oauthErr.Code = "invalid_request"
	}

	if cmd != nil && cmd.RedirectURI != "" {
		// 只要 redirect_uri 看起来可用，就优先把错误重定向给 client，
		// 这符合 authorization endpoint 的常见交互方式。
		redirectURL, buildErr := buildAuthorizeErrorRedirect(cmd.RedirectURI, oauthErr, cmd.State)
		if buildErr == nil {
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
	}

	http.Error(w, oauthErr.Description, http.StatusBadRequest)
}

func buildAuthorizeErrorRedirect(redirectURI string, oauthErr pkgoauth2.Error, state string) (string, error) {
	// 授权失败也要保留 state，避免前端无法把这次错误和原始请求对上。
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("error", oauthErr.Code)
	if oauthErr.Description != "" {
		q.Set("error_description", oauthErr.Description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func withReturnTo(loginURI, returnTo string) string {
	// return_to 是浏览器侧流程衔接的关键：登录/同意页完成后靠它回跳原请求。
	u, err := url.Parse(loginURI)
	if err != nil {
		return loginURI
	}
	q := u.Query()
	q.Set("return_to", returnTo)
	u.RawQuery = q.Encode()
	return u.String()
}
