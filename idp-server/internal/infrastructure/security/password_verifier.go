package security

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var ErrUnsupportedPasswordHash = errors.New("unsupported password hash")

// PasswordVerifier 封装密码哈希与比对逻辑。
// 当前实现使用 bcrypt，不接受任何明文前缀旁路。
type PasswordVerifier struct{}

func NewPasswordVerifier() *PasswordVerifier {
	return &PasswordVerifier{}
}

func (v *PasswordVerifier) HashPassword(password string) (string, error) {
	// 新密码统一按 bcrypt 默认成本系数生成哈希。
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func (v *PasswordVerifier) VerifyPassword(password, encodedHash string) error {
	// 空哈希直接视为不支持，避免把“没有密码”误判成校验失败。
	if strings.TrimSpace(encodedHash) == "" {
		return ErrUnsupportedPasswordHash
	}

	return bcrypt.CompareHashAndPassword([]byte(encodedHash), []byte(password))
}
