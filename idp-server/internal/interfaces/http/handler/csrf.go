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
	// CSRF token 采用“双重提交 cookie”模式：
	// 浏览器持有 cookie，表单或自定义 header 再回传同一个值。
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
	// 允许 token 来自表单字段或 X-CSRF-Token 头，兼容页面提交和 JS 请求。
	submittedToken = strings.TrimSpace(submittedToken)
	if submittedToken == "" {
		submittedToken = strings.TrimSpace(c.GetHeader(csrfHeaderName))
	}

	cookieToken := strings.TrimSpace(readCSRFCookie(c))
	if submittedToken == "" || cookieToken == "" {
		return errInvalidCSRFToken
	}
	// 常量时间比较避免在理论上泄露 token 匹配长度/前缀信息。
	if subtle.ConstantTimeCompare([]byte(submittedToken), []byte(cookieToken)) != 1 {
		return errInvalidCSRFToken
	}
	return nil
}

func writeCSRFError(c *gin.Context) {
	// 页面流给一个简单 HTML 响应，API 流给 JSON 错误。
	if wantsHTML(c.GetHeader("Accept")) {
		c.Data(http.StatusForbidden, "text/html; charset=utf-8", []byte("invalid csrf token"))
		return
	}
	c.JSON(http.StatusForbidden, gin.H{"error": errInvalidCSRFToken.Error()})
}

func newCSRFToken() (string, error) {
	// 32 字节随机数经 base64url 编码，足够满足一次会话级别的防伪需求。
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func readCSRFCookie(c *gin.Context) string {
	// 读取失败统一返回空串，让上层按“token 缺失”处理即可。
	token, err := c.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return token
}
