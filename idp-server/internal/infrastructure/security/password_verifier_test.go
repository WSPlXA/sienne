package security

import (
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordVerifierRejectsPlainPrefixBypass(t *testing.T) {
	verifier := NewPasswordVerifier()
	err := verifier.VerifyPassword("secret", "plain:secret")
	if err == nil {
		t.Fatal("VerifyPassword() error = nil, want non-nil")
	}
}

func TestPasswordVerifierAcceptsValidBcryptHash(t *testing.T) {
	verifier := NewPasswordVerifier()
	hash, err := verifier.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if err := verifier.VerifyPassword("secret", hash); err != nil {
		t.Fatalf("VerifyPassword() error = %v, want nil", err)
	}
}

func TestPasswordVerifierRejectsEmptyHash(t *testing.T) {
	verifier := NewPasswordVerifier()
	err := verifier.VerifyPassword("secret", "   ")
	if !errors.Is(err, ErrUnsupportedPasswordHash) {
		t.Fatalf("VerifyPassword() error = %v, want %v", err, ErrUnsupportedPasswordHash)
	}
}

func TestPasswordVerifierRejectsWrongPassword(t *testing.T) {
	verifier := NewPasswordVerifier()
	hash, err := verifier.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	err = verifier.VerifyPassword("wrong", hash)
	if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("VerifyPassword() error = %v, want %v", err, bcrypt.ErrMismatchedHashAndPassword)
	}
}
