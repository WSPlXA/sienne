package redis

import "fmt"

type KeyBuilder struct {
	Prefix string
	Env    string
}

func NewKeyBuilder(prefix, env string) *KeyBuilder {
	return &KeyBuilder{
		Prefix: prefix,
		Env:    env,
	}
}

func (k *KeyBuilder) Session(sessionID string) string {
	return fmt.Sprintf("%s:%s:session:sid:%s", k.Prefix, k.Env, sessionID)
}

func (k *KeyBuilder) UserSessionIndex(userID string) string {
	return fmt.Sprintf("%s:%s:session:user:%s", k.Prefix, k.Env, userID)
}

func (k *KeyBuilder) AuthCode(code string) string {
	return fmt.Sprintf("%s:%s:authcode:code:%s", k.Prefix, k.Env, code)
}

func (k *KeyBuilder) AuthCodeConsumed(code string) string {
	return fmt.Sprintf("%s:%s:authcode:consumed:%s", k.Prefix, k.Env, code)
}

func (k *KeyBuilder) OAuthState(state string) string {
	return fmt.Sprintf("%s:%s:oauthstate:%s", k.Prefix, k.Env, state)
}

func (k *KeyBuilder) Nonce(nonce string) string {
	return fmt.Sprintf("%s:%s:nonce:%s", k.Prefix, k.Env, nonce)
}

func (k *KeyBuilder) AccessToken(tokenSHA256 string) string {
	return fmt.Sprintf("%s:%s:token:access:sha256:%s", k.Prefix, k.Env, tokenSHA256)
}

func (k *KeyBuilder) RefreshToken(tokenSHA256 string) string {
	return fmt.Sprintf("%s:%s:token:refresh:sha256:%s", k.Prefix, k.Env, tokenSHA256)
}

func (k *KeyBuilder) RevokedAccessToken(tokenSHA256 string) string {
	return fmt.Sprintf("%s:%s:revoked:access:%s", k.Prefix, k.Env, tokenSHA256)
}

func (k *KeyBuilder) RevokedRefreshToken(tokenSHA256 string) string {
	return fmt.Sprintf("%s:%s:revoked:refresh:%s", k.Prefix, k.Env, tokenSHA256)
}

func (k *KeyBuilder) RefreshTokenGrace(tokenSHA256 string) string {
	return fmt.Sprintf("%s:%s:token:refresh:grace:%s", k.Prefix, k.Env, tokenSHA256)
}

func (k *KeyBuilder) RefreshTokenFamilyRevoked(familyID string) string {
	return fmt.Sprintf("%s:%s:token:refresh:family:revoked:%s", k.Prefix, k.Env, familyID)
}

func (k *KeyBuilder) LoginFailUser(username string) string {
	return fmt.Sprintf("%s:%s:loginfail:user:%s", k.Prefix, k.Env, username)
}

func (k *KeyBuilder) LoginFailIP(ip string) string {
	return fmt.Sprintf("%s:%s:loginfail:ip:%s", k.Prefix, k.Env, ip)
}

func (k *KeyBuilder) UserLock(userID string) string {
	return fmt.Sprintf("%s:%s:lock:user:%s", k.Prefix, k.Env, userID)
}

func (k *KeyBuilder) IPLock(ip string) string {
	return fmt.Sprintf("%s:%s:lock:ip:%s", k.Prefix, k.Env, ip)
}

func (k *KeyBuilder) LoginBlacklistUser(username string) string {
	return fmt.Sprintf("%s:%s:loginblacklist:user:%s", k.Prefix, k.Env, username)
}

func (k *KeyBuilder) DeviceCode(deviceCode string) string {
	return fmt.Sprintf("%s:%s:device:code:%s", k.Prefix, k.Env, deviceCode)
}

func (k *KeyBuilder) DeviceUserCode(userCode string) string {
	return fmt.Sprintf("%s:%s:device:user:%s", k.Prefix, k.Env, userCode)
}

func (k *KeyBuilder) TOTPEnrollment(sessionID string) string {
	return fmt.Sprintf("%s:%s:mfa:totp:enroll:%s", k.Prefix, k.Env, sessionID)
}

func (k *KeyBuilder) MFAChallenge(challengeID string) string {
	return fmt.Sprintf("%s:%s:mfa:challenge:%s", k.Prefix, k.Env, challengeID)
}

func (k *KeyBuilder) TOTPStepUsed(userID, purpose string, step int64) string {
	return fmt.Sprintf("%s:%s:mfa:totp:used:%s:%s:%d", k.Prefix, k.Env, userID, purpose, step)
}
