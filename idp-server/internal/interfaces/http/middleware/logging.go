package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	ContextRequestID = "request_id"
	RequestIDHeader  = "X-Request-ID"
)

type LoggingMiddleware struct {
	logger *log.Logger
}

func NewLoggingMiddleware(logger *log.Logger) *LoggingMiddleware {
	return &LoggingMiddleware{logger: logger}
}

func (m *LoggingMiddleware) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 日志中间件在请求开始时分配 request id，在结束后统一记录摘要。
		startedAt := time.Now()
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery
		requestID := resolveRequestID(c)
		c.Set(ContextRequestID, requestID)
		c.Writer.Header().Set(RequestIDHeader, requestID)

		c.Next()

		if rawQuery != "" {
			path = path + "?" + rawQuery
		}

		logger := m.logger
		if logger == nil {
			logger = log.Default()
		}

		logger.Printf(
			// 尽量把排障常用字段都收进一行：request id、client、subject、耗时、状态码。
			"http request_id=%s method=%s path=%s status=%d duration=%s ip=%s client_id=%s subject=%s ua=%q errors=%d",
			requestID,
			c.Request.Method,
			path,
			c.Writer.Status(),
			time.Since(startedAt).Round(time.Millisecond),
			c.ClientIP(),
			resolveClientID(c),
			resolveSubject(c),
			c.Request.UserAgent(),
			len(c.Errors),
		)
	}
}

func resolveRequestID(c *gin.Context) string {
	// 优先沿用上游代理传入的 request id，便于跨服务链路关联。
	requestID := strings.TrimSpace(c.GetHeader(RequestIDHeader))
	if requestID != "" {
		return requestID
	}

	var raw [12]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return base64.RawURLEncoding.EncodeToString(raw[:])
	}

	return time.Now().UTC().Format("20060102T150405.000000000")
}

func resolveClientID(c *gin.Context) string {
	// client_id 优先取鉴权中间件已解析结果，其次再从 query/form/basic auth 猜测。
	if value, ok := c.Get(ContextClientID); ok {
		if clientID, ok := value.(string); ok && clientID != "" {
			return clientID
		}
	}

	if clientID := strings.TrimSpace(c.Query("client_id")); clientID != "" {
		return clientID
	}
	if clientID := strings.TrimSpace(c.PostForm("client_id")); clientID != "" {
		return clientID
	}

	if auth := strings.TrimSpace(c.GetHeader("Authorization")); strings.HasPrefix(auth, "Basic ") {
		payload := strings.TrimPrefix(auth, "Basic ")
		if decoded, err := base64.StdEncoding.DecodeString(payload); err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[0])
			}
		}
	}

	return ""
}

func resolveSubject(c *gin.Context) string {
	// subject 同样优先复用上下文，避免重复解析 token claim。
	if value, ok := c.Get(ContextSubject); ok {
		if subject, ok := value.(string); ok && subject != "" {
			return subject
		}
	}

	if value, ok := c.Get(ContextTokenClaims); ok {
		if claims, ok := value.(map[string]any); ok {
			if subject, ok := claims["sub"].(string); ok {
				return subject
			}
		}
	}

	return ""
}
