package security

import "time"

// TOTPProvider 抽象一次性口令生成与校验逻辑。
// VerifyCodeWithStep 额外暴露匹配到的时间步，用于做重放保护。
type TOTPProvider interface {
	GenerateSecret() (string, error)
	ProvisioningURI(issuer, accountName, secret string) string
	VerifyCode(secret, code string, now time.Time) bool
	VerifyCodeWithStep(secret, code string, now time.Time) (bool, int64)
}
