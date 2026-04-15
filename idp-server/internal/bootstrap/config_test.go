package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigFromFileWithEnvOverride(t *testing.T) {
	clearConfigEnv(t)

	configFile := writeTempConfig(t, `
app:
  env: dev
mysql:
  dsn: user:pass@tcp(localhost:3306)/idp?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci
redis:
  addr: 127.0.0.1:6379
issuer: http://from-file.example.com
audit:
  batch_size: 32
  stream: custom-audit-stream
federated_oidc:
  scopes:
    - openid
    - profile
`)
	t.Setenv("IDP_CONFIG_FILE", configFile)
	t.Setenv("ISSUER", "https://from-env.example.com")
	t.Setenv("AUDIT_MAX_RETRY_COUNT", "21")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if got, want := cfg.Issuer, "https://from-env.example.com"; got != want {
		t.Fatalf("issuer = %q, want %q", got, want)
	}
	if got, want := cfg.MySQLDSN, "user:pass@tcp(localhost:3306)/idp?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci"; got != want {
		t.Fatalf("mysql dsn = %q, want %q", got, want)
	}
	if got, want := cfg.RedisAddr, "127.0.0.1:6379"; got != want {
		t.Fatalf("redis addr = %q, want %q", got, want)
	}
	if got, want := cfg.AuditBatchSize, 32; got != want {
		t.Fatalf("audit batch size = %d, want %d", got, want)
	}
	if got, want := cfg.AuditMaxRetryCount, 21; got != want {
		t.Fatalf("audit max retry count = %d, want %d", got, want)
	}
	if got, want := cfg.AuditStream, "custom-audit-stream"; got != want {
		t.Fatalf("audit stream = %q, want %q", got, want)
	}
	if len(cfg.FederatedOIDCScopes) != 2 || cfg.FederatedOIDCScopes[0] != "openid" || cfg.FederatedOIDCScopes[1] != "profile" {
		t.Fatalf("federated scopes = %#v", cfg.FederatedOIDCScopes)
	}
}

func TestLoadConfigBuildsAddressesFromComponents(t *testing.T) {
	clearConfigEnv(t)

	configFile := writeTempConfig(t, `
app:
  env: dev
mysql:
  host: db
  port: "3307"
  database: idp
  user: app
  password: secret
redis:
  host: cache
  port: "6380"
issuer: http://localhost:8080
`)
	t.Setenv("IDP_CONFIG_FILE", configFile)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if got, want := cfg.MySQLDSN, "app:secret@tcp(db:3307)/idp?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci"; got != want {
		t.Fatalf("mysql dsn = %q, want %q", got, want)
	}
	if got, want := cfg.RedisAddr, "cache:6380"; got != want {
		t.Fatalf("redis addr = %q, want %q", got, want)
	}
}

func TestLoadConfigValidationFailure(t *testing.T) {
	clearConfigEnv(t)

	configFile := writeTempConfig(t, `
app:
  env: prod
mysql:
  dsn: user:pass@tcp(localhost:3306)/idp?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci
redis:
  addr: 127.0.0.1:6379
totp:
  secret_encryption_key: prod-secret-key
issuer: localhost:8080
audit:
  batch_size: 0
`)
	t.Setenv("IDP_CONFIG_FILE", configFile)

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig() error = nil, want validation error")
	}
	message := err.Error()
	if !strings.Contains(message, "audit.batch_size must be > 0") || !strings.Contains(message, "issuer must include a host") {
		t.Fatalf("validation error = %q", message)
	}
}

func TestLoadConfigParsesEnvStringSlices(t *testing.T) {
	clearConfigEnv(t)

	configFile := writeTempConfig(t, `
app:
  env: dev
mysql:
  dsn: user:pass@tcp(localhost:3306)/idp?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci
redis:
  addr: 127.0.0.1:6379
issuer: http://localhost:8080
`)
	t.Setenv("IDP_CONFIG_FILE", configFile)
	t.Setenv("PASSKEY_RP_ORIGINS", "https://a.example.com, https://b.example.com")
	t.Setenv("FEDERATED_OIDC_SCOPES", "openid email profile")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if got, want := len(cfg.PasskeyRPOrigins), 2; got != want {
		t.Fatalf("passkey origins len = %d, want %d", got, want)
	}
	if got, want := len(cfg.FederatedOIDCScopes), 3; got != want {
		t.Fatalf("federated scopes len = %d, want %d", got, want)
	}
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "idp.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func clearConfigEnv(t *testing.T) {
	t.Helper()
	for _, binding := range configEnvBindings {
		for _, envName := range binding.envs {
			t.Setenv(envName, "")
		}
	}
	t.Setenv("IDP_CONFIG_FILE", "")
	t.Setenv("IDP_CONFIG_NAME", "")
	t.Setenv("IDP_CONFIG_TYPE", "")
	t.Setenv("IDP_CONFIG_PATHS", "")
	t.Setenv("IDP_REMOTE_CONFIG_ENABLED", "")
}

func TestResolveConfigSearchPathsExpandsHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	paths := resolveConfigSearchPaths([]string{"~/config", "./config"})
	if len(paths) != 2 {
		t.Fatalf("paths len = %d, want 2", len(paths))
	}
	if !strings.Contains(paths[0], filepath.Join(home, "config")) {
		t.Fatalf("first path = %q", paths[0])
	}
}

func TestValidateConfigRejectsNonPositiveDurations(t *testing.T) {
	cfg := &config{
		MySQLDSN:                "dsn",
		RedisAddr:               "redis:6379",
		AppEnv:                  "dev",
		SessionTTL:              0,
		AuditBatchSize:          1,
		AuditDedupTTL:           time.Second,
		AuditRetryTTL:           time.Second,
		AuditBlockTimeout:       time.Second,
		AuditReclaimIdle:        time.Second,
		AuditReclaimInterval:    time.Second,
		AuditMaxRetryCount:      1,
		SigningKeyBits:          2048,
		SigningKeyCheckInterval: time.Second,
		SigningKeyRotateBefore:  time.Second,
		SigningKeyRetireAfter:   time.Second,
		LoginFailureWindow:      time.Second,
		LoginUserLockTTL:        time.Second,
		LoginMaxFailuresPerIP:   1,
		LoginMaxFailuresPerUser: 1,
		LoginUserLockThreshold:  1,
		FederatedOIDCStateTTL:   time.Second,
		Issuer:                  "http://localhost:8080",
	}

	err := validateConfig(cfg)
	if err == nil || !strings.Contains(err.Error(), "session.ttl must be > 0") {
		t.Fatalf("validateConfig error = %v", err)
	}
}
