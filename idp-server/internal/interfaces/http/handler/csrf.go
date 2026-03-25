package handler

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	csrfCookieName   = "idp_csrf_token"
	csrfHeaderName   = "X-CSRF-Token"
	csrfCookieMaxAge = 12 * 60 * 60
)

var errInvalidCSRFToken = errors.New("invalid csrf token")

func ensureCSRFToken(c *gin.Context) (string, error) {
	if token := strings.TrimSpace(readCSRFCookie(c)); token != "" {
		return token, nil
	}

	token, err := newCSRFToken()
	if err != nil {
		return "", err
	}

	c.SetCookie(csrfCookieName, token, csrfCookieMaxAge, "/", "", false, false)
	return token, nil
}

func validateCSRFToken(c *gin.Context, submittedToken string) error {
	submittedToken = strings.TrimSpace(submittedToken)
	if submittedToken == "" {
		submittedToken = strings.TrimSpace(c.GetHeader(csrfHeaderName))
	}

	cookieToken := strings.TrimSpace(readCSRFCookie(c))
	if submittedToken == "" || cookieToken == "" {
		return errInvalidCSRFToken
	}
	if subtle.ConstantTimeCompare([]byte(submittedToken), []byte(cookieToken)) != 1 {
		return errInvalidCSRFToken
	}
	return nil
}

func writeCSRFError(c *gin.Context) {
	if wantsHTML(c.GetHeader("Accept")) {
		c.Data(http.StatusForbidden, "text/html; charset=utf-8", []byte("invalid csrf token"))
		return
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error()})
}

func newCSRFToken() (string, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func readCSRFCookie(c *gin.Context) string {
	token, err := c.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return token
}
