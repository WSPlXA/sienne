package handler

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"

	apptoken "idp-server/internal/application/token"
	"idp-server/internal/interfaces/http/dto"
	pkgoauth2 "idp-server/pkg/oauth2"

	"github.com/gin-gonic/gin"
)

type TokenHandler struct {
	tokenService apptoken.Exchanger
}

func NewTokenHandler(tokenService apptoken.Exchanger) *TokenHandler {
	return &TokenHandler{tokenService: tokenService}
}

func (h *TokenHandler) Handle(c *gin.Context) {
	var req dto.TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "invalid_request",
			Description: "invalid token request",
		})
		return
	}

	if err := req.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, pkgoauth2.Error{
			Code:        "invalid_request",
			Description: err.Error(),
		})
		return
	}

	clientID, clientSecret := resolveClientCredentials(c.GetHeader("Authorization"), req.ClientID, req.ClientSecret)
	result, err := h.tokenService.Exchange(c.Request.Context(), apptoken.ExchangeInput{
		GrantType:    pkgoauth2.GrantType(req.GrantType),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Code:         req.Code,
		RedirectURI:  req.RedirectURI,
		CodeVerifier: req.CodeVerifier,
		RefreshToken: req.RefreshToken,
		Scopes:       req.ScopeList(),
	})
	if err != nil {
		log.Printf("token exchange failed grant_type=%s client_id=%s err=%v", req.GrantType, clientID, err)
		status := http.StatusBadRequest
		oauthErr := pkgoauth2.Error{
			Code:        "invalid_grant",
			Description: err.Error(),
		}

		switch {
		case errors.Is(err, apptoken.ErrInvalidClient):
			status = http.StatusUnauthorized
			oauthErr.Code = "invalid_client"
		case errors.Is(err, apptoken.ErrInvalidScope):
			oauthErr.Code = "invalid_scope"
		case errors.Is(err, apptoken.ErrUnsupportedGrantType):
			oauthErr.Code = "unsupported_grant_type"
		case errors.Is(err, apptoken.ErrInvalidCode),
			errors.Is(err, apptoken.ErrInvalidRedirectURI),
			errors.Is(err, apptoken.ErrInvalidCodeVerifier),
			errors.Is(err, apptoken.ErrInvalidRefreshToken):
			oauthErr.Code = "invalid_grant"
		default:
			status = http.StatusInternalServerError
			oauthErr.Code = "server_error"
			oauthErr.Description = "token issuance failed"
		}

		c.JSON(status, oauthErr)
		return
	}

	c.JSON(http.StatusOK, pkgoauth2.TokenResponse{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		Scope:        result.Scope,
		RefreshToken: result.RefreshToken,
		IDToken:      result.IDToken,
	})
}

func resolveClientCredentials(authorizationHeader, bodyClientID, bodyClientSecret string) (string, string) {
	if strings.HasPrefix(authorizationHeader, "Basic ") {
		payload := strings.TrimPrefix(authorizationHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return parts[0], parts[1]
			}
		}
	}

	return bodyClientID, bodyClientSecret
}
