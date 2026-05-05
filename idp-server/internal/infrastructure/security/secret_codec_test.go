package security

import (
	"strings"
	"testing"
)

func TestSecretCodecEncryptDecryptRoundTrip(t *testing.T) {
	codec, err := NewSecretCodec("ChangeThisTOTPSecretKey32Chars!!")
	if err != nil {
		t.Fatalf("NewSecretCodec() error = %v", err)
	}

	encrypted, err := codec.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if encrypted == "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Encrypt() returned plain text")
	}
	if !strings.HasPrefix(encrypted, secretEncPrefix) {
		t.Fatalf("Encrypt() prefix = %q, want %q", encrypted, secretEncPrefix)
	}

	decrypted, err := codec.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if decrypted != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Decrypt() = %q, want %q", decrypted, "JBSWY3DPEHPK3PXP")
	}
}

func TestSecretCodecDecryptPlaintextCompatibility(t *testing.T) {
	codec, err := NewSecretCodec("ChangeThisTOTPSecretKey32Chars!!")
	if err != nil {
		t.Fatalf("NewSecretCodec() error = %v", err)
	}

	decrypted, err := codec.Decrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if decrypted != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Decrypt() = %q, want plain text passthrough", decrypted)
	}
}

func TestNewSecretCodecRejectsInvalidKeyLength(t *testing.T) {
	if _, err := NewSecretCodec("short-key"); err == nil {
		t.Fatalf("NewSecretCodec() error = nil, want non-nil")
	}
}
