package rbac

const (
	DomainAuth   uint32 = 0xF0000000
	DomainOAuth  uint32 = 0x0F000000
	DomainClient uint32 = 0x00F00000
	DomainUser   uint32 = 0x000F0000
	DomainAudit  uint32 = 0x0000F000
	DomainKey    uint32 = 0x00000F00
	DomainTenant uint32 = 0x000000F0
	DomainOps    uint32 = 0x0000000F
)

const (
	ActionRead   uint32 = 0x8
	ActionExec   uint32 = 0x4
	ActionManage uint32 = 0x2
	ActionPriv   uint32 = 0x1
)

const (
	AuthRead   uint32 = ActionRead << 28
	AuthExec   uint32 = ActionExec << 28
	AuthManage uint32 = ActionManage << 28
	AuthPriv   uint32 = ActionPriv << 28

	OAuthRead   uint32 = ActionRead << 24
	OAuthExec   uint32 = ActionExec << 24
	OAuthManage uint32 = ActionManage << 24
	OAuthPriv   uint32 = ActionPriv << 24

	ClientRead   uint32 = ActionRead << 20
	ClientExec   uint32 = ActionExec << 20
	ClientManage uint32 = ActionManage << 20
	ClientPriv   uint32 = ActionPriv << 20

	UserRead   uint32 = ActionRead << 16
	UserExec   uint32 = ActionExec << 16
	UserManage uint32 = ActionManage << 16
	UserPriv   uint32 = ActionPriv << 16

	AuditRead   uint32 = ActionRead << 12
	AuditExec   uint32 = ActionExec << 12
	AuditManage uint32 = ActionManage << 12
	AuditPriv   uint32 = ActionPriv << 12

	KeyRead   uint32 = ActionRead << 8
	KeyExec   uint32 = ActionExec << 8
	KeyManage uint32 = ActionManage << 8
	KeyPriv   uint32 = ActionPriv << 8

	TenantRead   uint32 = ActionRead << 4
	TenantExec   uint32 = ActionExec << 4
	TenantManage uint32 = ActionManage << 4
	TenantPriv   uint32 = ActionPriv << 4

	OpsRead   uint32 = ActionRead
	OpsExec   uint32 = ActionExec
	OpsManage uint32 = ActionManage
	OpsPriv   uint32 = ActionPriv
)

const (
	RoleEndUser       = "end_user"
	RoleSupport       = "support"
	RoleOAuthAdmin    = "oauth_admin"
	RoleSecurityAdmin = "security_admin"
	RoleSuperAdmin    = "super_admin"
)

const (
	MaskEndUser       uint32 = 0x00000000
	MaskAuditor       uint32 = 0x88888888
	MaskSupport       uint32 = 0xCC8C888C
	MaskOAuthAdmin    uint32 = 0x8EEC8888
	MaskSecurityAdmin uint32 = 0xEEEEEAEE
	MaskSuperAdmin    uint32 = 0xFFFFFFFF
)

func HasAll(mask uint32, required ...uint32) bool {
	for _, permission := range required {
		if permission == 0 {
			continue
		}
		if mask&permission != permission {
			return false
		}
	}
	return true
}

func HasAny(mask uint32, required ...uint32) bool {
	for _, permission := range required {
		if permission != 0 && mask&permission == permission {
			return true
		}
	}
	return false
}
