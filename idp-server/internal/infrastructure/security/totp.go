package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type TOTPProvider struct {
	period int64
	digits int
	skew   int64
}

func NewTOTPProvider() *TOTPProvider {
	// 默认采用常见的 30 秒时间步、6 位数字，并允许前后各 1 个时间窗的轻微时钟漂移。
	return &TOTPProvider{
		period: 30,
		digits: 6,
		skew:   1,
	}
}

func (p *TOTPProvider) GenerateSecret() (string, error) {
	// 20 字节随机种子经 base32 编码后作为 TOTP secret。
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="), nil
}

func (p *TOTPProvider) ProvisioningURI(issuer, accountName, secret string) string {
	// otpauth URI 用于让认证器应用扫码导入配置。
	issuer = strings.TrimSpace(issuer)
	accountName = strings.TrimSpace(accountName)
	label := url.PathEscape(accountName)
	if issuer != "" {
		label = url.PathEscape(issuer + ":" + accountName)
	}
	values := url.Values{}
	values.Set("secret", secret)
	if issuer != "" {
		values.Set("issuer", issuer)
	}
	values.Set("algorithm", "SHA1")
	values.Set("digits", fmt.Sprintf("%d", p.digits))
	values.Set("period", fmt.Sprintf("%d", p.period))
	return "otpauth://totp/" + label + "?" + values.Encode()
}

func (p *TOTPProvider) VerifyCode(secret, code string, now time.Time) bool {
	ok, _ := p.VerifyCodeWithStep(secret, code, now)
	return ok
}

func (p *TOTPProvider) VerifyCodeWithStep(secret, code string, now time.Time) (bool, int64) {
	// 返回 matched step 是为了让上层能对同一时间窗内的验证码做重放保护。
	code = strings.TrimSpace(code)
	if len(code) != p.digits {
		return false, 0
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return false, 0
	}
	counter := now.UTC().Unix() / p.period
	for offset := -p.skew; offset <= p.skew; offset++ {
		step := counter + offset
		if p.generateCode(key, step) == code {
			return true, step
		}
	}
	return false, 0
}

func (p *TOTPProvider) generateCode(key []byte, counter int64) string {
	// 按 HOTP/TOTP 标准做动态截断并映射成固定长度数字验证码。
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	truncated := int(binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff)
	modulo := 1
	for i := 0; i < p.digits; i++ {
		modulo *= 10
	}
	return fmt.Sprintf("%0*d", p.digits, truncated%modulo)
}
