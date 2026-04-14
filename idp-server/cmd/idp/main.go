package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"idp-server/internal/bootstrap"
)

const defaultListenAddr = ":8080"

func main() {
	// main 只负责两件事：
	// 1. 通过 bootstrap.Wire 构建完整的应用依赖图。
	// 2. 用构建好的 Router 启动 HTTP 服务。
	// 具体的业务初始化、仓储装配和路由注册都下沉到 bootstrap 层，
	// 这样入口文件可以保持足够薄，便于排查启动问题。
	app, err := bootstrap.Wire()
	if err != nil {
		log.Fatalf("bootstrap error: %v", err)
	}

	// 这里统一配置服务端超时，避免慢连接长期占用资源。
	// 对身份认证服务来说，这些超时属于基础防护的一部分：
	// ReadHeaderTimeout / ReadTimeout 用来限制请求读取阶段，
	// WriteTimeout 限制响应写出时间，IdleTimeout 则控制 keep-alive 连接空闲时长。
	server := &http.Server{
		Addr:              getEnvString("LISTEN_ADDR", defaultListenAddr),
		Handler:           app.Router,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("listening on %s", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server error: %v", err)
	}
}

func getEnvString(key, fallback string) string {
	// 环境变量允许运维覆盖默认值；空字符串按未配置处理，
	// 这样可以避免把“显式传了空值”误当成有效配置。
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
