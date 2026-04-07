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
	"idp-server/internal/application/authz"
	appclient "idp-server/internal/application/client"
	appclientauth "idp-server/internal/application/clientauth"
	appconsent "idp-server/internal/application/consent"
	appdevice "idp-server/internal/application/device"
	appmfa "idp-server/internal/application/mfa"
	"idp-server/internal/application/oidc"
	apprbac "idp-server/internal/application/rbac"
	appregister "idp-server/internal/application/register"
	appsession "idp-server/internal/application/session"
	apptoken "idp-server/internal/application/token"
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

// Wire设置应用程序的依赖关系并返回一个App实例。它加载配置，初始化数据库和缓存连接，创建存储库和服务，并构建HTTP路由器。
type App struct {
	Router http.Handler
}

// 本方法挂载在App结构体上，负责设置应用程序的依赖关系并返回一个App实例。它加载配置，初始化数据库和缓存连接，创建存储库和服务，并构建HTTP路由器。
func Wire() (*App, error) {
	// 加载配置从环境变量中获取应用程序的配置参数。如果某些必需的配置项缺失或无效，函数将返回错误。
	cfg, err := loadConfigFromEnv()
	// 如果加载配置失败，返回错误。
	if err != nil {
		return nil, err
	}
	// 创建一个带有超时的上下文，用于后续的数据库和缓存连接初始化。
	// 入参context.Background()表示从根上下文开始，5*time.Second表示设置超时时间为5秒。defer cancel()确保在函数返回时取消上下文，释放相关资源。
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	//首先是db，它是通过调用storage.NewMySQL函数创建的，该函数接受上下文和MySQL数据源名称（DSN）作为参数。如果连接数据库失败，函数将返回错误。
	db, err := storage.NewMySQL(ctx, cfg.MySQLDSN)
	if err != nil {
		return nil, err
	}

	// 接下来是redisClient，它是通过调用storage.NewRedis函数创建的，该函数接受上下文、Redis地址、密码和数据库索引作为参数。如果连接Redis失败，函数将关闭之前打开的数据库连接并返回错误。
	redisClient, err := storage.NewRedis(ctx, cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	// 创建存储库和服务实例。这里创建了多个存储库实例，如userRepo、sessionRepo、clientRepo等，以及多个服务实例，如authzService、consentService、authnService等。这些实例将用于处理应用程序的业务逻辑。
	keyBuilder := cacheRedis.NewKeyBuilder(cfg.RedisKeyPrefix, cfg.AppEnv)
	// userRepo是一个用户存储库实例，用于与数据库交互以管理用户数据。
	userRepo := persistence.NewUserRepository(db)
	operatorRoleRepo := persistence.NewOperatorRoleRepository(db)
	// sessionRepo是一个会话存储库实例，用于与数据库交互以管理会话数据。!【重要】
	sessionRepo := persistence.NewSessionRepository(db)
	// clientRepo是一个客户端存储库实例，用于与数据库交互以管理客户端数据。
	clientRepo := persistence.NewClientRepository(db)
	// authCodeRepo是一个授权码存储库实例，用于与数据库交互以管理授权码数据。
	authCodeRepo := persistence.NewAuthorizationCodeRepository(db)
	// consentRepo是一个consent存储库实例，用于与数据库交互以管理consent数据。
	consentRepo := persistence.NewConsentRepository(db)
	// jwkRepo是一个jwk存储库实例，用于与数据库交互以管理jwk数据。
	jwkRepo := persistence.NewJWKKeyRepository(db)
	// tokenRepo是一个token存储库实例，用于与数据库交互以管理token数据。
	tokenRepo := persistence.NewTokenRepository(db)
	// secretCodec是一个用于加密和解密TOTP秘密的编解码器实例。它使用配置中的TOTPSecretEncryptionKey进行初始化。如果初始化失败，函数将关闭之前打开的数据库和Redis连接并返回错误。
	// 为什么初始化失败要关闭数据库和Redis连接？因为如果编解码器无法正确初始化，应用程序可能无法安全地处理TOTP秘密，这可能会导致安全风险。因此，在这种情况下，最好关闭数据库和Redis连接以防止潜在的安全问题。
	secretCodec, err := infrasecurity.NewSecretCodec(cfg.TOTPSecretEncryptionKey)
	if err != nil {
		_ = db.Close()
		_ = redisClient.Close()
		return nil, fmt.Errorf("init totp secret codec: %w", err)
	}
	// 创建更多的存储库实例，如totpRepo、sessionCache、tokenCache等，这些存储库将用于管理TOTP数据、会话缓存、令牌缓存等。
	// repositories代表应用程序中与数据存储相关的组件，负责与数据库或缓存系统交互以存储和检索数据。这些存储库实例将被服务层使用，以实现应用程序的业务逻辑。
	// cacheRepositories代表应用程序中与缓存相关的组件，负责与缓存系统（如Redis）交互以存储和检索数据。这些缓存存储库实例将被服务层使用，以提高应用程序的性能和响应速度。
	totpRepo := persistence.NewTOTPRepository(db, secretCodec)
	// 比如sessionCache是一个会话缓存存储库实例，用于与Redis交互以管理会话缓存数据。它使用redisClient和keyBuilder进行初始化。
	sessionCache := cacheRedis.NewSessionCacheRepository(redisClient, keyBuilder)
	tokenCache := cacheRedis.NewTokenCacheRepository(redisClient, keyBuilder)
	deviceCodeRepo := cacheRedis.NewDeviceCodeRepository(redisClient, keyBuilder)
	mfaCache := cacheRedis.NewMFARepository(redisClient, keyBuilder)
	replayProtectionRepo := cacheRedis.NewReplayProtectionRepository(redisClient, keyBuilder)
	rateLimitRepo := cacheRedis.NewRateLimitRepository(redisClient, keyBuilder)
	passwordVerifier := infrasecurity.NewPasswordVerifier()
	totpProvider := infrasecurity.NewTOTPProvider()
	authzService := authz.NewService(clientRepo, sessionRepo, authCodeRepo, consentRepo, 10*time.Minute)
	consentService := appconsent.NewService(clientRepo, sessionRepo, sessionCache, consentRepo)
	registerService := appregister.NewService(userRepo, passwordVerifier)
	clientService := appclient.NewService(clientRepo, passwordVerifier)
	federatedOIDCProvider := buildFederatedOIDCProvider(cfg, replayProtectionRepo)
	authnRegistry := pluginregistry.NewAuthnRegistry(
		authnpassword.NewMethod(userRepo, passwordVerifier),
		authnfederatedoidc.NewMethod(federatedOIDCProvider),
	)
	// 上述都是在应用程序中使用的服务实例，这些服务实例封装了应用程序的业务逻辑，并使用存储库和缓存存储库来管理数据。它们将被HTTP处理程序使用，以处理来自客户端的请求并生成响应。
	// 例如，authnService是一个认证服务实例，用于处理用户认证相关的业务逻辑。它使用userRepo、sessionRepo、sessionCache、rateLimitRepo、mfaCache、authnRegistry、totpRepo、totpProvider等组件进行初始化，并配置了会话TTL、登录失败窗口、强制MFA注册等参数。
	authnService := authn.NewService(userRepo, sessionRepo, sessionCache, rateLimitRepo, mfaCache, authnRegistry, totpRepo, totpProvider, cfg.SessionTTL, 5*time.Minute, cfg.ForceMFAEnrollment, authn.RateLimitPolicy{
		FailureWindow:      cfg.LoginFailureWindow,
		MaxFailuresPerIP:   int64(cfg.LoginMaxFailuresPerIP),
		MaxFailuresPerUser: int64(cfg.LoginMaxFailuresPerUser),
		UserLockThreshold:  int64(cfg.LoginUserLockThreshold),
		UserLockTTL:        cfg.LoginUserLockTTL,
	})
	sessionService := appsession.NewService(sessionRepo, sessionCache, tokenRepo, tokenCache)
	rbacService := apprbac.NewService(operatorRoleRepo, userRepo)
	mfaService := appmfa.NewService(sessionRepo, sessionCache, userRepo, totpRepo, mfaCache, totpProvider, cfg.Issuer, 10*time.Minute)
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

	return &App{
		Router: interfacehttp.NewRouter(authzService, consentService, registerService, clientService, clientService, clientService, clientService, authnService, federatedOIDCProvider != nil, sessionService, rbacService, clientAuthenticator, grantRegistry, deviceService, mfaService, oidcService, authMiddleware, adminMiddleware),
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
	SessionTTL                    time.Duration
	Issuer                        string
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
		SessionTTL:                    getEnvDuration("SESSION_TTL", 8*time.Hour),
		Issuer:                        getEnvString("ISSUER", "http://localhost:8080"),
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
		TOTPSecretEncryptionKey:       strings.TrimSpace(os.Getenv("TOTP_SECRET_ENCRYPTION_KEY")),
	}
	// 如果加载配置失败，返回错误。
	if cfg.MySQLDSN == "" {
		cfg.MySQLDSN = buildMySQLDSNFromEnv()
	}
	if cfg.RedisAddr == "" {
		cfg.RedisAddr = buildRedisAddrFromEnv()
	}
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
