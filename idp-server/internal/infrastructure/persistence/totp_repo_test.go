package persistence

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	infrasecurity "idp-server/internal/infrastructure/security"

	_ "modernc.org/sqlite"
)

func TestTOTPRepositoryEncryptDecryptSecret(t *testing.T) {
	codec, err := infrasecurity.NewSecretCodec("ChangeThisTOTPSecretKey32Chars!!")
	if err != nil {
		t.Fatalf("NewSecretCodec() error = %v", err)
	}
	repo := NewTOTPRepository(nil, codec)
	stored, err := repo.encryptSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("encryptSecret() error = %v", err)
	}
	if stored == "JBSWY3DPEHPK3PXP" {
		t.Fatalf("stored secret should be encrypted, got plain text")
	}
	if !strings.HasPrefix(stored, "enc:v1:") {
		t.Fatalf("stored secret prefix = %q, want enc:v1:", stored)
	}
	plain, err := repo.decryptSecret(stored)
	if err != nil {
		t.Fatalf("decryptSecret() error = %v", err)
	}
	if plain != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("decryptSecret() = %q, want %q", plain, "JBSWY3DPEHPK3PXP")
	}
}

func TestTOTPRepositoryFindSupportsLegacyPlaintextRow(t *testing.T) {
	db := mustNewSQLiteTOTPDB(t)
	defer func() { _ = db.Close() }()

	now := time.Date(2026, 4, 6, 10, 0, 0, 0, time.UTC)
	if _, err := db.Exec(
		`INSERT INTO user_totp_credentials (user_id, secret, enabled_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		2,
		"LEGACYPLAINTEXTSECRET",
		now,
		now,
		now,
	); err != nil {
		t.Fatalf("insert legacy row error = %v", err)
	}

	codec, err := infrasecurity.NewSecretCodec("ChangeThisTOTPSecretKey32Chars!!")
	if err != nil {
		t.Fatalf("NewSecretCodec() error = %v", err)
	}
	repo := NewTOTPRepository(db, codec)
	model, err := repo.FindByUserID(context.Background(), 2)
	if err != nil {
		t.Fatalf("FindByUserID() error = %v", err)
	}
	if model == nil || model.Secret != "LEGACYPLAINTEXTSECRET" {
		t.Fatalf("FindByUserID().Secret = %#v, want legacy plain text", model)
	}
}

func mustNewSQLiteTOTPDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	schema := `
CREATE TABLE user_totp_credentials (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL UNIQUE,
	secret TEXT NOT NULL,
	enabled_at DATETIME NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL
);`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		t.Fatalf("create schema error = %v", err)
	}
	return db
}
