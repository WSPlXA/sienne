package audit

import "time"

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
