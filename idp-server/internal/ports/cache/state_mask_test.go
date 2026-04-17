package cache

import (
	"testing"
	"time"
)

func TestNormalizeSessionStateMaskAndStatus(t *testing.T) {
	mask := NormalizeSessionStateMask(0, "active")
	if mask != SessionStateActive {
		t.Fatalf("NormalizeSessionStateMask(active) = %d, want %d", mask, SessionStateActive)
	}
	if status := SessionStatusFromMask(mask, ""); status != "active" {
		t.Fatalf("SessionStatusFromMask(active) = %q, want active", status)
	}

	loggedOut := NormalizeSessionStateMask(0, "logged_out")
	if loggedOut != SessionStateLoggedOut {
		t.Fatalf("NormalizeSessionStateMask(logged_out) = %d, want %d", loggedOut, SessionStateLoggedOut)
	}
	if IsSessionStateActive(loggedOut) {
		t.Fatalf("IsSessionStateActive(logged_out) = true, want false")
	}
}

func TestIsSessionEntryActive(t *testing.T) {
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	entry := &SessionCacheEntry{
		Status:    "active",
		StateMask: SessionStateActive,
		ExpiresAt: now.Add(time.Minute),
	}
	if !IsSessionEntryActive(entry, now) {
		t.Fatalf("IsSessionEntryActive(active) = false, want true")
	}

	entry.StateMask = SessionStateLoggedOut
	if IsSessionEntryActive(entry, now) {
		t.Fatalf("IsSessionEntryActive(logged_out) = true, want false")
	}
}

func TestNormalizeMFAChallengeStateMask(t *testing.T) {
	mask := NormalizeMFAChallengeStateMask(0, "passkey_totp_fallback", "pending", "")
	if mask&MFAChallengeStateModePasskey == 0 {
		t.Fatalf("mode passkey bit missing, mask=%d", mask)
	}
	if mask&MFAChallengeStateModePush != 0 {
		t.Fatalf("push mode should be off for passkey mode, mask=%d", mask)
	}

	pushApproved := NormalizeMFAChallengeStateMask(mask, "push_totp_fallback", "approved", "")
	if pushApproved&MFAChallengeStateModePush == 0 {
		t.Fatalf("mode push bit missing, mask=%d", pushApproved)
	}
	if pushApproved&MFAChallengeStatePushApproved == 0 {
		t.Fatalf("push approved bit missing, mask=%d", pushApproved)
	}
	if pushApproved&MFAChallengeStatePushDenied != 0 {
		t.Fatalf("push denied should be off when approved, mask=%d", pushApproved)
	}
}

func TestMFAModeAndPushStatusFromStateMask(t *testing.T) {
	mask := MFAChallengeStateLive | MFAChallengeStateModePush | MFAChallengeStatePushDenied
	if mode := MFAModeFromStateMask(mask, "totp_only"); mode != "push_totp_fallback" {
		t.Fatalf("MFAModeFromStateMask() = %q, want push_totp_fallback", mode)
	}
	if status := MFAPushStatusFromStateMask(mask, "pending"); status != "denied" {
		t.Fatalf("MFAPushStatusFromStateMask() = %q, want denied", status)
	}
}
