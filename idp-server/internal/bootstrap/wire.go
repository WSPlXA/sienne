package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"idp-server/internal/application/authn"
	appclient "idp-server/internal/application/client"
	appconsent "idp-server/internal/application/consent"
	"idp-server/internal/application/oidc"
	appregister "idp-server/internal/application/register"
	appsession "idp-server/internal/application/session"
	"idp-server/internal/application/authz"
	apptoken "idp-server/internal/application/token"
	cacheRedis "idp-server/internal/infrastructure/cache/redis"
	infracrypto "idp-server/internal/infrastructure/crypto"
	"idp-server/internal/infrastructure/persistence"
	infrasecurity "idp-server/internal/infrastructure/security"
	"idp-server/internal/infrastructure/storage"
	interfacehttp "idp-server/internal/interfaces/http"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"
)

type App struct {
	Router http.Handler
}

func Wire() (*App, error) {
	cfg, err := loadConfigFromEnv()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	db, err := storage.NewMySQL(ctx, cfg.MySQLDSN)
	if err != nil {
		return nil, err
	}

	redisClient, err := storage.NewRedis(ctx, cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	keyBuilder := cacheRedis.NewKeyBuilder(cfg.RedisKeyPrefix, cfg.AppEnv)
	userRepo := persistence.NewUserRepository(db)
	sessionRepo := persistence.NewSessionRepository(db)
	clientRepo := persistence.NewClientRepository(db)
	authCodeRepo := persistence.NewAuthorizationCodeRepository(db)
	consentRepo := persistence.NewConsentRepository(db)
	jwkRepo := persistence.NewJWKKeyRepository(db)
	tokenRepo := persistence.NewTokenRepository(db)
	sessionCache := cacheRedis.NewSessionCacheRepository(redisClient, keyBuilder)
	tokenCache := cacheRedis.NewTokenCacheRepository(redisClient, keyBuilder)
	passwordVerifier := infrasecurity.NewPasswordVerifier()
	authzService := authz.NewService(clientRepo, sessionRepo, authCodeRepo, consentRepo, 10*time.Minute)
	consentService := appconsent.NewService(clientRepo, sessionRepo, sessionCache, consentRepo)
	registerService := appregister.NewService(userRepo, passwordVerifier)
	clientService := appclient.NewService(clientRepo, passwordVerifier)
	authnService := authn.NewService(userRepo, sessionRepo, sessionCache, passwordVerifier, cfg.SessionTTL)
	sessionService := appsession.NewService(sessionRepo, sessionCache)
	rotationConfig := infracrypto.RotationConfig{
		WorkingDir:    cfg.WorkDir,
		StorageDir:    cfg.SigningKeyDir,
		KeyBits:       cfg.SigningKeyBits,
		CheckInterval: cfg.SigningKeyCheckInterval,
		RotateBefore:  cfg.SigningKeyRotateBefore,
		RetireAfter:   cfg.SigningKeyRetireAfter,
		KIDPrefix:     "kid",
	}
	keyManager, err := infracrypto.EnsureKeyManager(ctx, jwkRepo, rotationConfig)
	if err != nil {
		keyManager, err = infracrypto.NewGeneratedRSAKeyManager(cfg.JWTKeyID, cfg.SigningKeyBits)
		if err != nil {
			_ = db.Close()
			_ = redisClient.Close()
			return nil, err
		}
	} else {
		infracrypto.StartRotationLoop(jwkRepo, keyManager, rotationConfig)
	}
	jwtService := infracrypto.NewJWTService(infracrypto.NewSigner(keyManager))
	tokenService := apptoken.NewService(
		authCodeRepo,
		clientRepo,
		userRepo,
		tokenRepo,
		tokenCache,
		passwordVerifier,
		jwtService,
		cfg.Issuer,
	)
	oidcService := oidc.NewService(userRepo, &jwtServiceAdapter{service: jwtService}, keyManagerAdapter{manager: keyManager}, cfg.Issuer)
	authMiddleware := httpmiddleware.NewAuthMiddleware(&jwtMiddlewareAdapter{service: jwtService}, tokenCache, cfg.Issuer)

	return &App{
		Router: interfacehttp.NewRouter(authzService, consentService, registerService, clientService, clientService, authnService, sessionService, tokenService, oidcService, authMiddleware),
	}, nil
}

type config struct {
	MySQLDSN                 string
	RedisAddr                string
	RedisPassword            string
	RedisDB                  int
	RedisKeyPrefix           string
	AppEnv                   string
	SessionTTL               time.Duration
	Issuer                   string
	JWTKeyID                 string
	WorkDir                  string
	SigningKeyDir           string
	SigningKeyBits          int
	SigningKeyCheckInterval time.Duration
	SigningKeyRotateBefore  time.Duration
	SigningKeyRetireAfter   time.Duration
}

func loadConfigFromEnv() (*config, error) {
	cfg := &config{
		MySQLDSN:                 strings.TrimSpace(os.Getenv("MYSQL_DSN")),
		RedisAddr:                strings.TrimSpace(os.Getenv("REDIS_ADDR")),
		RedisPassword:            strings.TrimSpace(os.Getenv("REDIS_PASSWORD")),
		RedisDB:                  getEnvInt("REDIS_DB", 0),
		RedisKeyPrefix:           getEnvString("REDIS_KEY_PREFIX", "idp"),
		AppEnv:                   getEnvString("APP_ENV", "dev"),
		SessionTTL:               getEnvDuration("SESSION_TTL", 8*time.Hour),
		Issuer:                   getEnvString("ISSUER", "http://localhost:8080"),
		JWTKeyID:                 getEnvString("JWT_KEY_ID", "kid-2026-01-rs256"),
		WorkDir:                  getWorkingDir(),
		SigningKeyDir:           getEnvString("SIGNING_KEY_DIR", "scripts/dev_keys"),
		SigningKeyBits:          getEnvInt("SIGNING_KEY_BITS", 2048),
		SigningKeyCheckInterval: getEnvDuration("SIGNING_KEY_CHECK_INTERVAL", 1*time.Hour),
		SigningKeyRotateBefore:  getEnvDuration("SIGNING_KEY_ROTATE_BEFORE", 24*time.Hour),
		SigningKeyRetireAfter:   getEnvDuration("SIGNING_KEY_RETIRE_AFTER", 24*time.Hour),
	}

	if cfg.MySQLDSN == "" {
		cfg.MySQLDSN = buildMySQLDSNFromEnv()
	}
	if cfg.RedisAddr == "" {
		cfg.RedisAddr = buildRedisAddrFromEnv()
	}

	if cfg.MySQLDSN == "" {
		return nil, fmt.Errorf("missing mysql configuration: set MYSQL_DSN or MYSQL_HOST/MYSQL_DATABASE/MYSQL_USER/MYSQL_PASSWORD")
	}
	if cfg.RedisAddr == "" {
		return nil, fmt.Errorf("missing redis configuration: set REDIS_ADDR or REDIS_HOST")
	}

	return cfg, nil
}

func getWorkingDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func buildMySQLDSNFromEnv() string {
	host := strings.TrimSpace(os.Getenv("MYSQL_HOST"))
	database := strings.TrimSpace(os.Getenv("MYSQL_DATABASE"))
	user := strings.TrimSpace(os.Getenv("MYSQL_USER"))
	password := os.Getenv("MYSQL_PASSWORD")
	port := getEnvString("MYSQL_PORT", "3306")

	if host == "" || database == "" || user == "" || password == "" {
		return ""
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
		user,
		password,
		host,
		port,
		database,
	)
}

func buildRedisAddrFromEnv() string {
	host := strings.TrimSpace(os.Getenv("REDIS_HOST"))
	port := getEnvString("REDIS_PORT", "6379")
	if host == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", host, port)
}

func getEnvString(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

type jwtServiceAdapter struct {
	service *infracrypto.JWTService
}

func (a *jwtServiceAdapter) ParseAndValidate(token string, opts oidc.ValidateOptions) (map[string]any, error) {
	return a.service.ParseAndValidate(token, infracrypto.ValidateOptions{
		Issuer: opts.Issuer,
	})
}

type jwtMiddlewareAdapter struct {
	service *infracrypto.JWTService
}

func (a *jwtMiddlewareAdapter) ParseAndValidate(token string, opts httpmiddleware.ValidateOptions) (map[string]any, error) {
	return a.service.ParseAndValidate(token, infracrypto.ValidateOptions{
		Issuer: opts.Issuer,
	})
}

type keyManagerAdapter struct {
	manager *infracrypto.KeyManager
}

func (a keyManagerAdapter) PublicJWKS() []oidc.JSONWebKey {
	if a.manager == nil {
		return nil
	}

	keys := a.manager.PublicJWKS()
	result := make([]oidc.JSONWebKey, 0, len(keys))
	for _, key := range keys {
		result = append(result, oidc.JSONWebKey{
			Kty: key.Kty,
			Kid: key.Kid,
			Use: key.Use,
			Alg: key.Alg,
			N:   key.N,
			E:   key.E,
		})
	}
	return result
}
