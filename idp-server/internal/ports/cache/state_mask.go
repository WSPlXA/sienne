package cache

import (
	"strings"
	"time"
)

const (
	// SessionStateActive 表示会话可用于业务访问。
	SessionStateActive uint32 = 1 << iota
	// SessionStateLocked 表示会话被安全策略阻断。
	SessionStateLocked
	// SessionStateLoggedOut 表示会话已被显式登出。
	SessionStateLoggedOut
)

const (
	// MFAChallengeStateLive 表示挑战记录仍可被消费。
	MFAChallengeStateLive uint32 = 1 << iota
	// MFAChallengeStateModePasskey 表示当前挑战允许 Passkey 分支。
	MFAChallengeStateModePasskey
	// MFAChallengeStateModePush 表示当前挑战允许 Push 分支。
	MFAChallengeStateModePush
	// MFAChallengeStatePushApproved 表示 Push 已批准。
	MFAChallengeStatePushApproved
	// MFAChallengeStatePushDenied 表示 Push 已拒绝。
	MFAChallengeStatePushDenied
	// MFAChallengeStatePasskeySessionBound 表示已绑定 passkey login session。
	MFAChallengeStatePasskeySessionBound
)

const (
	mfaModeTOTPOnly            = "totp_only"
	mfaModePushTOTPFallback    = "push_totp_fallback"
	mfaModePasskeyTOTPFallback = "passkey_totp_fallback"

	mfaPushStatusPending  = "pending"
	mfaPushStatusApproved = "approved"
	mfaPushStatusDenied   = "denied"
)

// NormalizeSessionStateMask 把字符串状态压缩为可按位判断的整数掩码。
func NormalizeSessionStateMask(mask uint32, status string) uint32 {
	if mask != 0 {
		return mask
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "logged_out", "logout":
		return SessionStateLoggedOut
	case "locked":
		return SessionStateLocked
	default:
		return SessionStateActive
	}
}

// SessionStatusFromMask 从位掩码恢复兼容旧接口的字符串状态。
func SessionStatusFromMask(mask uint32, fallback string) string {
	mask = NormalizeSessionStateMask(mask, fallback)
	if mask&SessionStateLoggedOut != 0 {
		return "logged_out"
	}
	if mask&SessionStateLocked != 0 {
		return "locked"
	}
	return "active"
}

// IsSessionStateActive 返回该掩码是否处于可用状态。
func IsSessionStateActive(mask uint32) bool {
	return mask&SessionStateActive != 0 &&
		mask&SessionStateLocked == 0 &&
		mask&SessionStateLoggedOut == 0
}

// IsSessionEntryActive 同时校验状态位和过期时间，避免上层重复做字符串比较。
func IsSessionEntryActive(entry *SessionCacheEntry, now time.Time) bool {
	if entry == nil || !entry.ExpiresAt.After(now) {
		return false
	}
	return IsSessionStateActive(NormalizeSessionStateMask(entry.StateMask, entry.Status))
}

// NormalizeMFAChallengeStateMask 统一生成挑战状态位，避免 mode/status 字符串分支扩散。
func NormalizeMFAChallengeStateMask(mask uint32, mode, pushStatus, passkeySessionJSON string) uint32 {
	if mask == 0 {
		mask = MFAChallengeStateLive
	}

	mask &^= MFAChallengeStateModePush | MFAChallengeStateModePasskey
	switch normalizeMFAMode(mode) {
	case mfaModePushTOTPFallback:
		mask |= MFAChallengeStateModePush
	case mfaModePasskeyTOTPFallback:
		mask |= MFAChallengeStateModePasskey
	}

	mask &^= MFAChallengeStatePushApproved | MFAChallengeStatePushDenied
	switch normalizeMFAPushStatus(pushStatus) {
	case mfaPushStatusApproved:
		mask |= MFAChallengeStatePushApproved
	case mfaPushStatusDenied:
		mask |= MFAChallengeStatePushDenied
	}

	if strings.TrimSpace(passkeySessionJSON) != "" {
		mask |= MFAChallengeStatePasskeySessionBound
	}

	return canonicalMFAChallengeStateMask(mask, passkeySessionJSON)
}

// MFAModeFromStateMask 从状态位恢复兼容旧流程的 mode。
func MFAModeFromStateMask(mask uint32, fallback string) string {
	mask = canonicalMFAChallengeStateMask(mask, "")
	switch {
	case mask&MFAChallengeStateModePush != 0:
		return mfaModePushTOTPFallback
	case mask&MFAChallengeStateModePasskey != 0:
		return mfaModePasskeyTOTPFallback
	default:
		trimmed := strings.ToLower(strings.TrimSpace(fallback))
		switch trimmed {
		case mfaModeTOTPOnly, mfaModePushTOTPFallback, mfaModePasskeyTOTPFallback:
			return trimmed
		default:
			if trimmed != "" {
				return trimmed
			}
			return mfaModeTOTPOnly
		}
	}
}

// MFAPushStatusFromStateMask 从状态位恢复兼容旧流程的 push status。
func MFAPushStatusFromStateMask(mask uint32, fallback string) string {
	mask = canonicalMFAChallengeStateMask(mask, "")
	switch {
	case mask&MFAChallengeStatePushDenied != 0:
		return mfaPushStatusDenied
	case mask&MFAChallengeStatePushApproved != 0:
		return mfaPushStatusApproved
	default:
		return normalizeMFAPushStatus(fallback)
	}
}

func canonicalMFAChallengeStateMask(mask uint32, passkeySessionJSON string) uint32 {
	mask |= MFAChallengeStateLive

	// mode 互斥：push 优先于 passkey，避免双模式并存导致分支歧义。
	if mask&MFAChallengeStateModePush != 0 {
		mask &^= MFAChallengeStateModePasskey
	}

	// 非 push 模式下，push 决议位必须清空。
	if mask&MFAChallengeStateModePush == 0 {
		mask &^= MFAChallengeStatePushApproved | MFAChallengeStatePushDenied
	}

	// approved/denied 冲突时按 fail-closed 处理为 denied。
	if mask&MFAChallengeStatePushApproved != 0 && mask&MFAChallengeStatePushDenied != 0 {
		mask &^= MFAChallengeStatePushApproved
	}

	if strings.TrimSpace(passkeySessionJSON) == "" {
		mask &^= MFAChallengeStatePasskeySessionBound
	} else {
		mask |= MFAChallengeStatePasskeySessionBound
	}

	return mask
}

func normalizeMFAMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case mfaModePushTOTPFallback:
		return mfaModePushTOTPFallback
	case mfaModePasskeyTOTPFallback:
		return mfaModePasskeyTOTPFallback
	default:
		return mfaModeTOTPOnly
	}
}

func normalizeMFAPushStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case mfaPushStatusApproved:
		return mfaPushStatusApproved
	case mfaPushStatusDenied:
		return mfaPushStatusDenied
	default:
		return mfaPushStatusPending
	}
}
