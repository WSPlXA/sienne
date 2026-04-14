package session

import "time"

// Model 表示服务端维护的一条登录会话记录。
// 它是浏览器 session 的真相来源，可用于会话恢复、审计和强制下线。
type Model struct {
	ID              int64
	SessionID       string
	UserID          int64
	Subject         string
	ACR             string
	AMRJSON         string
	IPAddress       string
	UserAgent       string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
	LoggedOutAt     *time.Time
	CreatedAt       time.Time
}
