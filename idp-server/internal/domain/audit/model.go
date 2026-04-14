package audit

import "time"

// Model 表示一条安全/运维审计事件。
// 它会把主体、来源、会话和附加元数据一起记录下来，供后台审计台和追责使用。
type Model struct {
	ID           int64
	EventType    string
	ClientID     *int64
	UserID       *int64
	Subject      string
	SessionID    *int64
	IPAddress    string
	UserAgent    string
	MetadataJSON string
	CreatedAt    time.Time
}
