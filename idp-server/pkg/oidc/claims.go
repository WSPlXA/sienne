package oidc

// Claims 是 OIDC/JWT claims 的轻量 map 视图。
type Claims map[string]interface{}

const (
	// 下面是一组在本项目里会显式读写的标准 OIDC/JWT claim 名称。
	ClaimIssuer            = "iss"
	ClaimSubject           = "sub"
	ClaimAudience          = "aud"
	ClaimExpiration        = "exp"
	ClaimIssuedAt          = "iat"
	ClaimNotBefore         = "nbf"
	ClaimJWTID             = "jti"
	ClaimNonce             = "nonce"
	ClaimAuthorizedParty   = "azp"
	ClaimAuthTime          = "auth_time"
	ClaimName              = "name"
	ClaimPreferredUsername = "preferred_username"
	ClaimEmail             = "email"
	ClaimEmailVerified     = "email_verified"
)
