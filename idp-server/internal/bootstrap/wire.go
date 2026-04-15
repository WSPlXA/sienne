package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"idp-server/internal/application/authn"
	"idp-server/internal/application/authz"
	appclient "idp-server/internal/application/client"
	appclientauth "idp-server/internal/application/clientauth"
	appconsent "idp-server/internal/application/consent"
	appdevice "idp-server/internal/application/device"
	appkeys "idp-server/internal/application/keys"
	appmfa "idp-server/internal/application/mfa"
	"idp-server/internal/application/oidc"
	apppasskey "idp-server/internal/application/passkey"
	apprbac "idp-server/internal/application/rbac"
	appregister "idp-server/internal/application/register"
	appsession "idp-server/internal/application/session"
	apptoken "idp-server/internal/application/token"
	"idp-server/internal/infrastructure/auditstream"
	cacheRedis "idp-server/internal/infrastructure/cache/redis"
	infracrypto "idp-server/internal/infrastructure/crypto"
	infraexternal "idp-server/internal/infrastructure/external"
	"idp-server/internal/infrastructure/persistence"
	infrasecurity "idp-server/internal/infrastructure/security"
	"idp-server/internal/infrastructure/storage"
	interfacehttp "idp-server/internal/interfaces/http"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	authnfederatedoidc "idp-server/internal/plugins/authn/federated_oidc"
	authnpassword "idp-server/internal/plugins/authn/password"
	clientauthbasic "idp-server/internal/plugins/client_auth/client_secret_basic"
	clientauthpost "idp-server/internal/plugins/client_auth/client_secret_post"
	clientauthnone "idp-server/internal/plugins/client_auth/none"
	grantauthcode "idp-server/internal/plugins/grant/authorization_code"
	grantclientcred "idp-server/internal/plugins/grant/client_credentials"
	grantdevicecode "idp-server/internal/plugins/grant/device_code"
	grantpassword "idp-server/internal/plugins/grant/password"
	grantrefreshtoken "idp-server/internal/plugins/grant/refresh_token"
	pluginregistry "idp-server/internal/plugins/registry"
	cacheport "idp-server/internal/ports/cache"
)

// App 是启动阶段产出的顶层运行对象。
// 当前只暴露 Router，因为这个二进制的唯一职责是提供 HTTP 服务；
// 如果未来需要优雅停机、后台任务或健康探针对象，也可以继续在这里扩展。
type App struct {
	Router http.Handler
}

// Wire 把“配置 -> 基础设施 -> 仓储 -> 应用服务 -> HTTP 接口”这条依赖链一次性串起来。
// 这个函数是整个进程的 Composition Root：只有这里知道具体实现类型，
// 其余层只依赖接口或更窄的抽象，便于测试和后续替换实现。
func Wire() (*App, error) {
	// 第一步先收敛配置，避免后续初始化过程中夹杂大量环境变量读取逻辑。
	cfg, err := loadConfigFromEnv()
	if err != nil {
		return nil, err
	}

	// 初始化数据库、Redis、密钥管理器等外部依赖时统一套一个短超时，
	// 防止启动阶段因为下游不可用而无限阻塞。
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

	// 从这里开始进入依赖装配阶段：
	// persistence.* 负责落库，cacheRedis.* 负责短生命周期状态，
	// application service 则把多个仓储/缓存拼成一个完整用例。
	keyBuilder := cacheRedis.NewKeyBuilder(cfg.RedisKeyPrefix, cfg.AppEnv)
	userRepo := persistence.NewUserRepository(db)
	auditStore := persistence.NewAuditEventRepository(db)
	operatorRoleRepo := persistence.NewOperatorRoleRepository(db)
	sessionRepo := persistence.NewSessionRepository(db)
	clientRepo := persistence.NewClientRepository(db)
	authCodeRepo := persistence.NewAuthorizationCodeRepository(db)
	consentRepo := persistence.NewConsentRepository(db)
	jwkRepo := persistence.NewJWKKeyRepository(db)
	tokenRepo := persistence.NewTokenRepository(db)

	// TOTP 密钥会持久化到数据库，因此这里先建立密钥编解码器，
	// 保证后续仓储操作拿到的永远是“可安全解密”的实现。
	secretCodec, err := infrasecurity.NewSecretCodec(cfg.TOTPSecretEncryptionKey)
	if err != nil {
		_ = db.Close()
		_ = redisClient.Close()
		return nil, fmt.Errorf("init totp secret codec: %w", err)
	}
	totpRepo := persistence.NewTOTPRepository(db, secretCodec)
	passkeyRepo := persistence.NewPasskeyCredentialRepository(db)
	sessionCache := cacheRedis.NewSessionCacheRepository(redisClient, keyBuilder)
	tokenCache := cacheRedis.NewTokenCacheRepository(redisClient, keyBuilder)
	deviceCodeRepo := cacheRedis.NewDeviceCodeRepository(redisClient, keyBuilder)
	mfaCache := cacheRedis.NewMFARepository(redisClient, keyBuilder)
	replayProtectionRepo := cacheRedis.NewReplayProtectionRepository(redisClient, keyBuilder)
	rateLimitRepo := cacheRedis.NewRateLimitRepository(redisClient, keyBuilder)
	auditProducer := auditstream.NewProducer(redisClient, cfg.AuditStream, cfg.AuditDedupTTL, keyBuilder.AuditEventDedup)
	auditEventRepo := auditstream.NewAsyncRepository(auditStore, auditProducer, !cfg.AuditAsyncEnabled)
	if cfg.AuditAsyncEnabled {
		auditConsumer := auditstream.NewConsumer(redisClient, auditStore, auditstream.ConsumerConfig{
			Stream:          cfg.AuditStream,
			DLQStream:       cfg.AuditDLQStream,
			Group:           cfg.AuditConsumerGroup,
			Consumer:        cfg.AuditConsumerName,
			BatchSize:       int64(cfg.AuditBatchSize),
			BlockTimeout:    cfg.AuditBlockTimeout,
			ReclaimIdle:     cfg.AuditReclaimIdle,
			RetryTTL:        cfg.AuditRetryTTL,
			MaxRetryCount:   int64(cfg.AuditMaxRetryCount),
			ReclaimInterval: cfg.AuditReclaimInterval,
		}, keyBuilder.AuditRetryCounter)
		if err := auditConsumer.Start(context.Background()); err != nil {
			_ = db.Close()
			_ = redisClient.Close()
			return nil, fmt.Errorf("start audit async consumer: %w", err)
		}
	}
	passwordVerifier := infrasecurity.NewPasswordVerifier()
	totpProvider := infrasecurity.NewTOTPProvider()
	authzService := authz.NewService(clientRepo, sessionRepo, authCodeRepo, consentRepo, 10*time.Minute)
	consentService := appconsent.NewService(clientRepo, sessionRepo, sessionCache, consentRepo)
	registerService := appregister.NewService(userRepo, passwordVerifier, rateLimitRepo)
	clientService := appclient.NewService(clientRepo, passwordVerifier)
	federatedOIDCProvider := buildFederatedOIDCProvider(cfg, replayProtectionRepo)

	// 认证方式和 grant type 都通过 registry 扩展。
	// Wire 在这里决定启用哪些插件，业务层只关心“按类型查找并执行”。
	authnRegistry := pluginregistry.NewAuthnRegistry(
		authnpassword.NewMethod(userRepo, passwordVerifier),
		authnfederatedoidc.NewMethod(federatedOIDCProvider),
	)

	// authnService 是登录链路的核心编排器：
	// 它协调密码校验、失败限流、账户锁定、MFA 挑战和最终会话创建。
	authnService := authn.NewService(userRepo, sessionRepo, sessionCache, rateLimitRepo, mfaCache, authnRegistry, totpRepo, totpProvider, cfg.SessionTTL, 5*time.Minute, cfg.ForceMFAEnrollment, authn.RateLimitPolicy{
		FailureWindow:      cfg.LoginFailureWindow,
		MaxFailuresPerIP:   int64(cfg.LoginMaxFailuresPerIP),
		MaxFailuresPerUser: int64(cfg.LoginMaxFailuresPerUser),
		UserLockThreshold:  int64(cfg.LoginUserLockThreshold),
		UserLockTTL:        cfg.LoginUserLockTTL,
	})
	var passkeyProvider *infrasecurity.PasskeyProvider
	if cfg.PasskeyEnabled {
		// Passkey 对 RP 配置非常敏感，启动阶段就完成校验，
		// 比等到请求进来才报错更容易定位环境配置问题。
		rpID, rpDisplayName, rpOrigins, err := resolvePasskeyRPConfig(cfg)
		if err != nil {
			_ = db.Close()
			_ = redisClient.Close()
			return nil, fmt.Errorf("resolve passkey rp config: %w", err)
		}
		passkeyProvider, err = infrasecurity.NewPasskeyProvider(rpID, rpDisplayName, rpOrigins)
		if err != nil {
			_ = db.Close()
			_ = redisClient.Close()
			return nil, fmt.Errorf("init passkey provider: %w", err)
		}
		authnService.WithPasskey(passkeyRepo, passkeyProvider)
	}
	sessionService := appsession.NewService(sessionRepo, sessionCache, tokenRepo, tokenCache)
	rbacService := apprbac.NewService(operatorRoleRepo, userRepo)
	mfaService := appmfa.NewService(sessionRepo, sessionCache, userRepo, totpRepo, mfaCache, totpProvider, resolveTOTPIssuer(cfg), 10*time.Minute)
	var passkeyService apppasskey.Manager
	if passkeyProvider != nil {
		passkeyService = apppasskey.NewService(sessionRepo, sessionCache, userRepo, passkeyRepo, mfaCache, passkeyProvider, 10*time.Minute)
	}
	rotationConfig := infracrypto.RotationConfig{
		WorkingDir:    cfg.WorkDir,
		StorageDir:    cfg.SigningKeyDir,
		KeyBits:       cfg.SigningKeyBits,
		CheckInterval: cfg.SigningKeyCheckInterval,
		RotateBefore:  cfg.SigningKeyRotateBefore,
		RetireAfter:   cfg.SigningKeyRetireAfter,
		KIDPrefix:     "kid",
	}

	// 优先使用持久化密钥管理器，保证 JWKS 能稳定对外发布；
	// 只有在持久化初始化失败时才回退到进程内临时密钥，方便开发环境快速启动。
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
		deviceCodeRepo,
		passwordVerifier,
		jwtService,
		cfg.Issuer,
	)
	deviceService := appdevice.NewService(clientRepo, deviceCodeRepo, sessionRepo, sessionCache, 10*time.Minute, 5*time.Second)
	grantRegistry := pluginregistry.NewGrantRegistry(
		grantauthcode.NewHandler(tokenService),
		grantrefreshtoken.NewHandler(tokenService),
		grantclientcred.NewHandler(tokenService),
		grantpassword.NewHandler(tokenService),
		grantdevicecode.NewHandler(tokenService),
	)
	clientAuthRegistry := pluginregistry.NewClientAuthRegistry(
		clientauthbasic.NewAuthenticator(passwordVerifier),
		clientauthpost.NewAuthenticator(passwordVerifier),
		clientauthnone.NewAuthenticator(),
	)
	clientAuthenticator := appclientauth.NewService(clientRepo, clientAuthRegistry)
	oidcService := oidc.NewService(userRepo, tokenRepo, tokenCache, &jwtServiceAdapter{service: jwtService}, keyManagerAdapter{manager: keyManager}, cfg.Issuer)
	authMiddleware := httpmiddleware.NewAuthMiddleware(&jwtMiddlewareAdapter{service: jwtService}, tokenCache, cfg.Issuer)
	adminMiddleware := httpmiddleware.NewSessionPermissionMiddleware(sessionRepo, sessionCache, userRepo)
	keysService := appkeys.NewService(func(ctx context.Context) (*appkeys.RotateKeysResult, error) {
		result, err := infracrypto.RotateSigningKeyNow(ctx, jwkRepo, keyManager, rotationConfig)
		if err != nil {
			return nil, err
		}
		return &appkeys.RotateKeysResult{
			PreviousKID: result.PreviousKID,
			ActiveKID:   result.ActiveKID,
			RotatedAt:   result.RotatedAt,
			RotatesAt:   result.RotatesAt,
		}, nil
	})

	// 最后一层才把所有 service 暴露给 HTTP router。
	// 这样 handler 层保持“输入输出转换器”的角色，不直接感知底层实现细节。
	return &App{
		Router: interfacehttp.NewRouter(authzService, consentService, registerService, registerService, registerService, userRepo, clientService, clientService, clientService, clientService, authnService, federatedOIDCProvider != nil, sessionService, rbacService, keysService, auditEventRepo, clientAuthenticator, grantRegistry, deviceService, mfaService, passkeyService, oidcService, authMiddleware, adminMiddleware),
	}, nil
}

// 配置结构体定义了应用程序的配置参数，这些参数通常从环境变量中加载。loadConfigFromEnv函数负责从环境变量中加载配置，并设置默认值。如果某些必需的配置项缺失或无效，函数将返回错误。
type config struct {
	MySQLDSN                      string
	RedisAddr                     string
	RedisPassword                 string
	RedisDB                       int
	RedisKeyPrefix                string
	AppEnv                        string
	AuditAsyncEnabled             bool
	AuditStream                   string
	AuditDLQStream                string
	AuditConsumerGroup            string
	AuditConsumerName             string
	AuditBatchSize                int
	AuditDedupTTL                 time.Duration
	AuditRetryTTL                 time.Duration
	AuditBlockTimeout             time.Duration
	AuditReclaimIdle              time.Duration
	AuditReclaimInterval          time.Duration
	AuditMaxRetryCount            int
	SessionTTL                    time.Duration
	Issuer                        string
	TOTPIssuer                    string
	JWTKeyID                      string
	WorkDir                       string
	SigningKeyDir                 string
	SigningKeyBits                int
	SigningKeyCheckInterval       time.Duration
	SigningKeyRotateBefore        time.Duration
	SigningKeyRetireAfter         time.Duration
	FederatedOIDCIssuer           string
	FederatedOIDCClientID         string
	FederatedOIDCClientSecret     string
	FederatedOIDCRedirectURI      string
	FederatedOIDCClientAuthMethod string
	FederatedOIDCUsernameClaim    string
	FederatedOIDCDisplayNameClaim string
	FederatedOIDCEmailClaim       string
	FederatedOIDCScopes           []string
	FederatedOIDCStateTTL         time.Duration
	LoginFailureWindow            time.Duration
	LoginMaxFailuresPerIP         int
	LoginMaxFailuresPerUser       int
	LoginUserLockThreshold        int
	LoginUserLockTTL              time.Duration
	ForceMFAEnrollment            bool
	PasskeyEnabled                bool
	PasskeyRPID                   string
	PasskeyRPDisplayName          string
	PasskeyRPOrigins              []string
	TOTPSecretEncryptionKey       string
}

// loadConfigFromEnv函数负责从环境变量中加载配置，并设置默认值。如果某些必需的配置项缺失或无效，函数将返回错误。
func loadConfigFromEnv() (*config, error) {
	cfg := &config{
		MySQLDSN:                      strings.TrimSpace(os.Getenv("MYSQL_DSN")),
		RedisAddr:                     strings.TrimSpace(os.Getenv("REDIS_ADDR")),
		RedisPassword:                 strings.TrimSpace(os.Getenv("REDIS_PASSWORD")),
		RedisDB:                       getEnvInt("REDIS_DB", 0),
		RedisKeyPrefix:                getEnvString("REDIS_KEY_PREFIX", "idp"),
		AppEnv:                        getEnvString("APP_ENV", "dev"),
		AuditAsyncEnabled:             getEnvBool("AUDIT_ASYNC_ENABLED", true),
		AuditConsumerGroup:            getEnvString("AUDIT_CONSUMER_GROUP", "audit-writers"),
		AuditConsumerName:             getEnvString("AUDIT_CONSUMER_NAME", hostnameOrDefault("idp-server")),
		AuditBatchSize:                getEnvInt("AUDIT_BATCH_SIZE", 16),
		AuditDedupTTL:                 getEnvDuration("AUDIT_DEDUP_TTL", 24*time.Hour),
		AuditRetryTTL:                 getEnvDuration("AUDIT_RETRY_TTL", 24*time.Hour),
		AuditBlockTimeout:             getEnvDuration("AUDIT_BLOCK_TIMEOUT", 2*time.Second),
		AuditReclaimIdle:              getEnvDuration("AUDIT_RECLAIM_IDLE", 30*time.Second),
		AuditReclaimInterval:          getEnvDuration("AUDIT_RECLAIM_INTERVAL", 15*time.Second),
		AuditMaxRetryCount:            getEnvInt("AUDIT_MAX_RETRY_COUNT", 10),
		SessionTTL:                    getEnvDuration("SESSION_TTL", 8*time.Hour),
		Issuer:                        getEnvString("ISSUER", "http://localhost:8080"),
		TOTPIssuer:                    strings.TrimSpace(os.Getenv("TOTP_ISSUER")),
		JWTKeyID:                      getEnvString("JWT_KEY_ID", "kid-2026-01-rs256"),
		WorkDir:                       getWorkingDir(),
		SigningKeyDir:                 getEnvString("SIGNING_KEY_DIR", "scripts/dev_keys"),
		SigningKeyBits:                getEnvInt("SIGNING_KEY_BITS", 2048),
		SigningKeyCheckInterval:       getEnvDuration("SIGNING_KEY_CHECK_INTERVAL", 1*time.Hour),
		SigningKeyRotateBefore:        getEnvDuration("SIGNING_KEY_ROTATE_BEFORE", 24*time.Hour),
		SigningKeyRetireAfter:         getEnvDuration("SIGNING_KEY_RETIRE_AFTER", 24*time.Hour),
		FederatedOIDCIssuer:           strings.TrimSpace(os.Getenv("FEDERATED_OIDC_ISSUER")),
		FederatedOIDCClientID:         strings.TrimSpace(os.Getenv("FEDERATED_OIDC_CLIENT_ID")),
		FederatedOIDCClientSecret:     os.Getenv("FEDERATED_OIDC_CLIENT_SECRET"),
		FederatedOIDCRedirectURI:      strings.TrimSpace(os.Getenv("FEDERATED_OIDC_REDIRECT_URI")),
		FederatedOIDCClientAuthMethod: getEnvString("FEDERATED_OIDC_CLIENT_AUTH_METHOD", "client_secret_basic"),
		FederatedOIDCUsernameClaim:    getEnvString("FEDERATED_OIDC_USERNAME_CLAIM", "preferred_username"),
		FederatedOIDCDisplayNameClaim: getEnvString("FEDERATED_OIDC_DISPLAY_NAME_CLAIM", "name"),
		FederatedOIDCEmailClaim:       getEnvString("FEDERATED_OIDC_EMAIL_CLAIM", "email"),
		FederatedOIDCScopes:           getEnvFields("FEDERATED_OIDC_SCOPES", []string{"openid", "profile", "email"}),
		FederatedOIDCStateTTL:         getEnvDuration("FEDERATED_OIDC_STATE_TTL", 10*time.Minute),
		LoginFailureWindow:            getEnvDuration("LOGIN_FAILURE_WINDOW", 15*time.Minute),
		LoginMaxFailuresPerIP:         getEnvInt("LOGIN_MAX_FAILURES_PER_IP", 20),
		LoginMaxFailuresPerUser:       getEnvInt("LOGIN_MAX_FAILURES_PER_USER", 5),
		LoginUserLockThreshold:        getEnvInt("LOGIN_USER_LOCK_THRESHOLD", 5),
		LoginUserLockTTL:              getEnvDuration("LOGIN_USER_LOCK_TTL", 30*time.Minute),
		ForceMFAEnrollment:            getEnvBool("FORCE_MFA_ENROLLMENT", true),
		PasskeyEnabled:                getEnvBool("PASSKEY_ENABLED", true),
		PasskeyRPID:                   strings.TrimSpace(os.Getenv("PASSKEY_RP_ID")),
		PasskeyRPDisplayName:          getEnvString("PASSKEY_RP_DISPLAY_NAME", "IDP Server"),
		PasskeyRPOrigins:              getEnvFields("PASSKEY_RP_ORIGINS", nil),
		TOTPSecretEncryptionKey:       strings.TrimSpace(os.Getenv("TOTP_SECRET_ENCRYPTION_KEY")),
	}
	// 如果加载配置失败，返回错误。
	if cfg.MySQLDSN == "" {
		cfg.MySQLDSN = buildMySQLDSNFromEnv()
	}
	if cfg.RedisAddr == "" {
		cfg.RedisAddr = buildRedisAddrFromEnv()
	}
	keyBuilder := cacheRedis.NewKeyBuilder(cfg.RedisKeyPrefix, cfg.AppEnv)
	cfg.AuditStream = getEnvString("AUDIT_STREAM", keyBuilder.AuditStream())
	cfg.AuditDLQStream = getEnvString("AUDIT_DLQ_STREAM", keyBuilder.AuditDLQStream())
	if cfg.TOTPSecretEncryptionKey == "" {
		if strings.EqualFold(cfg.AppEnv, "dev") {
			cfg.TOTPSecretEncryptionKey = "dev_totp_secret_encryption_key!!"
		} else {
			return nil, fmt.Errorf("missing TOTP_SECRET_ENCRYPTION_KEY")
		}
	}

	if cfg.MySQLDSN == "" {
		return nil, fmt.Errorf("missing mysql configuration: set MYSQL_DSN or MYSQL_HOST/MYSQL_DATABASE/MYSQL_USER/MYSQL_PASSWORD")
	}
	if cfg.RedisAddr == "" {
		return nil, fmt.Errorf("missing redis configuration: set REDIS_ADDR or REDIS_HOST")
	}

	return cfg, nil
}

// getWorkingDir函数获取当前工作目录，如果获取失败则返回当前目录（"."）。这个函数用于确定应用程序的工作目录，以便在需要时访问文件系统。
// 因为我们的脚本和生成的密钥文件都放在项目根目录下的scripts/dev_keys目录中，所以工作目录应该设置为项目根目录。通过调用getWorkingDir函数，我们可以确保应用程序能够正确地找到和访问这些文件，无论它是从哪个目录启动的。
func getWorkingDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}

func hostnameOrDefault(fallback string) string {
	host, err := os.Hostname()
	if err != nil {
		return fallback
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return fallback
	}
	return host
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

// 布尔值的环境变量通常用于启用或禁用某些功能，例如是否强制MFA注册。getEnvBool函数从环境变量中获取布尔值，如果环境变量未设置或无法解析为布尔值，则返回默认值。
// 为什么要写这个函数？因为环境变量都是字符串类型的，而我们需要将它们转换为布尔值以便在代码中使用。通过编写getEnvBool函数，我们可以方便地从环境变量中获取布尔值，并且在环境变量未设置或无效时提供一个合理的默认值。这有助于提高代码的健壮性和可配置性。
func getEnvBool(key string, fallback bool) bool {
	// 从环境变量中获取布尔值，如果环境变量未设置或无法解析为布尔值，则返回默认值。
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	// 比如传入的是True、true、1等都应该被解析为true，False、false、0等都应该被解析为false。strconv.ParseBool函数可以处理这些常见的布尔值表示形式。
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return value
}

func getEnvFields(key string, fallback []string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return append([]string(nil), fallback...)
	}

	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return append([]string(nil), fallback...)
	}
	return fields
}

func buildFederatedOIDCProvider(cfg *config, replayCache cacheport.ReplayProtectionRepository) *infraexternal.OIDCProvider {
	if cfg == nil {
		return nil
	}
	if strings.TrimSpace(cfg.FederatedOIDCIssuer) == "" || strings.TrimSpace(cfg.FederatedOIDCClientID) == "" {
		return nil
	}

	return infraexternal.NewOIDCProviderWithReplayCache(infraexternal.OIDCProviderConfig{
		Issuer:           cfg.FederatedOIDCIssuer,
		ClientID:         cfg.FederatedOIDCClientID,
		ClientSecret:     cfg.FederatedOIDCClientSecret,
		RedirectURI:      cfg.FederatedOIDCRedirectURI,
		Scopes:           append([]string(nil), cfg.FederatedOIDCScopes...),
		ClientAuthMethod: cfg.FederatedOIDCClientAuthMethod,
		UsernameClaim:    cfg.FederatedOIDCUsernameClaim,
		DisplayNameClaim: cfg.FederatedOIDCDisplayNameClaim,
		EmailClaim:       cfg.FederatedOIDCEmailClaim,
		StateTTL:         cfg.FederatedOIDCStateTTL,
	}, replayCache)
}

func resolvePasskeyRPConfig(cfg *config) (string, string, []string, error) {
	if cfg == nil {
		return "", "", nil, fmt.Errorf("missing config")
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return "", "", nil, fmt.Errorf("missing issuer")
	}
	issuerURL, err := neturl.Parse(issuer)
	if err != nil {
		return "", "", nil, fmt.Errorf("parse issuer: %w", err)
	}
	if issuerURL.Scheme == "" || issuerURL.Host == "" {
		return "", "", nil, fmt.Errorf("invalid issuer origin")
	}

	rpID := strings.TrimSpace(cfg.PasskeyRPID)
	if rpID == "" {
		rpID = strings.TrimSpace(issuerURL.Hostname())
	}
	if rpID == "" {
		return "", "", nil, fmt.Errorf("missing passkey rp id")
	}

	origins := make([]string, 0, len(cfg.PasskeyRPOrigins)+1)
	for _, origin := range cfg.PasskeyRPOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		origins = append(origins, origin)
	}
	if len(origins) == 0 {
		origins = append(origins, issuerURL.Scheme+"://"+issuerURL.Host)
	}

	displayName := strings.TrimSpace(cfg.PasskeyRPDisplayName)
	if displayName == "" {
		displayName = "IDP Server"
	}

	return rpID, displayName, origins, nil
}

func resolveTOTPIssuer(cfg *config) string {
	if cfg == nil {
		return ""
	}
	display := strings.TrimSpace(cfg.TOTPIssuer)
	if display != "" {
		return display
	}
	issuer := strings.TrimSpace(cfg.Issuer)
	if issuer == "" {
		return ""
	}
	issuerURL, err := neturl.Parse(issuer)
	if err == nil {
		host := strings.TrimSpace(issuerURL.Hostname())
		if host != "" {
			return host
		}
	}
	return issuer
}

// jwtServiceAdapter和jwtMiddlewareAdapter是适配器结构体，用于将infracrypto.JWTService适配为应用程序中使用的JWT服务接口。这些适配器实现了相应的接口方法，并将调用委托给infracrypto.JWTService实例。
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
