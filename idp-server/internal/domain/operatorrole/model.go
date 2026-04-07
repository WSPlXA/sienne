package operatorrole

import "time"

type Model struct {
	ID            int64
	RoleCode      string
	DisplayName   string
	Description   string
	PrivilegeMask uint32
	IsSystem      bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
