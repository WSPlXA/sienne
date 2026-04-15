package bootstrap

import (
	"context"
	"database/sql"
	"net/http"
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
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"

	goredis "github.com/redis/go-redis/v9"
)

func provideMySQL(ctx context.Context, cfg *config) (*sql.DB, error) {
	return storage.NewMySQL(ctx, cfg.MySQLDSN)
}

func provideRedis(ctx context.Context, cfg *config) (*goredis.Client, error) {
	return storage.NewRedis(ctx, cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
}

func provideKeyBuilder(cfg *config) *cacheRedis.KeyBuilder {
	return cacheRedis.NewKeyBuilder(cfg.RedisKeyPrefix, cfg.AppEnv)
}

func provideSecretCodec(cfg *config) (*infrasecurity.SecretCodec, error) {
	return infrasecurity.NewSecretCodec(cfg.TOTPSecretEncryptionKey)
}

func providePasswordVerifier() securityport.PasswordVerifier {
	return infrasecurity.NewPasswordVerifier()
}

func provideTOTPProvider() securityport.TOTPProvider {
	return infrasecurity.NewTOTPProvider()
}

func providePasskeyProvider(cfg *config) (securityport.PasskeyProvider, error) {
	if !cfg.PasskeyEnabled {
		return nil, nil
	}
	rpID, displayName, origins, err := resolvePasskeyRPConfig(cfg)
	if err != nil {
		return nil, err
	}
	return infrasecurity.NewPasskeyProvider(rpID, displayName, origins)
}

func provideUserRepository(db *sql.DB) repository.UserRepository {
	return persistence.NewUserRepository(db)
}

func provideAuditStore(db *sql.DB) *persistence.AuditEventRepository {
	return persistence.NewAuditEventRepository(db)
}

func provideOperatorRoleRepository(db *sql.DB) repository.OperatorRoleRepository {
	return persistence.NewOperatorRoleRepository(db)
}

func provideSessionRepository(db *sql.DB) repository.SessionRepository {
	return persistence.NewSessionRepository(db)
}

func provideClientRepository(db *sql.DB) repository.ClientRepository {
	return persistence.NewClientRepository(db)
}

func provideAuthorizationCodeRepository(db *sql.DB) repository.AuthorizationCodeRepository {
	return persistence.NewAuthorizationCodeRepository(db)
}

func provideConsentRepository(db *sql.DB) repository.ConsentRepository {
	return persistence.NewConsentRepository(db)
}

func provideJWKRepository(db *sql.DB) *persistence.JWKKeyRepository {
	return persistence.NewJWKKeyRepository(db)
}

func provideTokenStore(db *sql.DB) *persistence.TokenRepository {
	return persistence.NewTokenRepository(db)
}

func provideTokenRepository(store *persistence.TokenRepository) repository.TokenRepository {
	return store
}

func provideTOTPRepository(db *sql.DB, codec *infrasecurity.SecretCodec) repository.TOTPRepository {
	return persistence.NewTOTPRepository(db, codec)
}

func providePasskeyRepository(db *sql.DB) repository.PasskeyCredentialRepository {
	return persistence.NewPasskeyCredentialRepository(db)
}

func provideSessionCacheRepository(rdb *goredis.Client, keyBuilder *cacheRedis.KeyBuilder) cacheport.SessionCacheRepository {
	return cacheRedis.NewSessionCacheRepository(rdb, keyBuilder)
}

func provideTokenCacheRepository(rdb *goredis.Client, keyBuilder *cacheRedis.KeyBuilder) cacheport.TokenCacheRepository {
	return cacheRedis.NewTokenCacheRepository(rdb, keyBuilder)
}

func provideDeviceCodeRepository(rdb *goredis.Client, keyBuilder *cacheRedis.KeyBuilder) cacheport.DeviceCodeRepository {
	return cacheRedis.NewDeviceCodeRepository(rdb, keyBuilder)
}

func provideMFARepository(rdb *goredis.Client, keyBuilder *cacheRedis.KeyBuilder) cacheport.MFARepository {
	return cacheRedis.NewMFARepository(rdb, keyBuilder)
}

func provideReplayProtectionRepository(rdb *goredis.Client, keyBuilder *cacheRedis.KeyBuilder) cacheport.ReplayProtectionRepository {
	return cacheRedis.NewReplayProtectionRepository(rdb, keyBuilder)
}

func provideRateLimitRepository(rdb *goredis.Client, keyBuilder *cacheRedis.KeyBuilder) cacheport.RateLimitRepository {
	return cacheRedis.NewRateLimitRepository(rdb, keyBuilder)
}

func provideAuditEventRepository(
	rdb *goredis.Client,
	cfg *config,
	keyBuilder *cacheRedis.KeyBuilder,
	auditStore *persistence.AuditEventRepository,
) (repository.AuditEventRepository, error) {
	producer := auditstream.NewProducer(rdb, cfg.AuditStream, cfg.AuditDedupTTL, keyBuilder.AuditEventDedup)
	repo := auditstream.NewAsyncRepository(auditStore, producer, !cfg.AuditAsyncEnabled)
	if !cfg.AuditAsyncEnabled {
		return repo, nil
	}

	consumer := auditstream.NewConsumer(rdb, auditStore, auditstream.ConsumerConfig{
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
	if err := consumer.Start(context.Background()); err != nil {
		return nil, err
	}
	return repo, nil
}

func provideFederatedOIDCProvider(cfg *config, replayCache cacheport.ReplayProtectionRepository) *infraexternal.OIDCProvider {
	return buildFederatedOIDCProvider(cfg, replayCache)
}

func provideAuthnRegistry(
	userRepo repository.UserRepository,
	passwordVerifier securityport.PasswordVerifier,
	federatedOIDCProvider *infraexternal.OIDCProvider,
) *pluginregistry.AuthnRegistry {
	return pluginregistry.NewAuthnRegistry(
		authnpassword.NewMethod(userRepo, passwordVerifier),
		authnfederatedoidc.NewMethod(federatedOIDCProvider),
	)
}

func provideAuthnService(
	cfg *config,
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	rateLimitRepo cacheport.RateLimitRepository,
	mfaCache cacheport.MFARepository,
	authnRegistry *pluginregistry.AuthnRegistry,
	totpRepo repository.TOTPRepository,
	totpProvider securityport.TOTPProvider,
	passkeyRepo repository.PasskeyCredentialRepository,
	passkeyProvider securityport.PasskeyProvider,
) authn.Authenticator {
	service := authn.NewService(userRepo, sessionRepo, sessionCache, rateLimitRepo, mfaCache, authnRegistry, totpRepo, totpProvider, cfg.SessionTTL, 5*time.Minute, cfg.ForceMFAEnrollment, authn.RateLimitPolicy{
		FailureWindow:      cfg.LoginFailureWindow,
		MaxFailuresPerIP:   int64(cfg.LoginMaxFailuresPerIP),
		MaxFailuresPerUser: int64(cfg.LoginMaxFailuresPerUser),
		UserLockThreshold:  int64(cfg.LoginUserLockThreshold),
		UserLockTTL:        cfg.LoginUserLockTTL,
	})
	if passkeyProvider != nil {
		service.WithPasskey(passkeyRepo, passkeyProvider)
	}
	return service
}

func provideAuthzService(
	clientRepo repository.ClientRepository,
	sessionRepo repository.SessionRepository,
	authCodeRepo repository.AuthorizationCodeRepository,
	consentRepo repository.ConsentRepository,
) authz.Service {
	return authz.NewService(clientRepo, sessionRepo, authCodeRepo, consentRepo, 10*time.Minute)
}

func provideConsentManager(
	clientRepo repository.ClientRepository,
	sessionRepo repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	consentRepo repository.ConsentRepository,
) appconsent.Manager {
	return appconsent.NewService(clientRepo, sessionRepo, sessionCache, consentRepo)
}

func provideRegisterService(
	userRepo repository.UserRepository,
	passwordVerifier securityport.PasswordVerifier,
	rateLimitRepo cacheport.RateLimitRepository,
) *appregister.Service {
	return appregister.NewService(userRepo, passwordVerifier, rateLimitRepo)
}

func provideRegistrar(service *appregister.Service) appregister.Registrar {
	return service
}

func providePasswordResetter(service *appregister.Service) appregister.PasswordResetter {
	return service
}

func provideAccountUnlocker(service *appregister.Service) appregister.AccountUnlocker {
	return service
}

func provideClientService(
	clientRepo repository.ClientRepository,
	passwordVerifier securityport.PasswordVerifier,
) *appclient.Service {
	return appclient.NewService(clientRepo, passwordVerifier)
}

func provideClientCreator(service *appclient.Service) appclient.Creator {
	return service
}

func provideClientRegistrar(service *appclient.Service) appclient.Registrar {
	return service
}

func provideClientPostLogoutRegistrar(service *appclient.Service) appclient.PostLogoutRegistrar {
	return service
}

func provideLogoutRedirectValidator(service *appclient.Service) appclient.LogoutRedirectValidator {
	return service
}

func provideSessionManager(
	sessionRepo repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	tokenStore *persistence.TokenRepository,
	tokenCache cacheport.TokenCacheRepository,
) appsession.Manager {
	return appsession.NewService(sessionRepo, sessionCache, tokenStore, tokenCache)
}

func provideRBACManager(
	operatorRoleRepo repository.OperatorRoleRepository,
	userRepo repository.UserRepository,
) apprbac.Manager {
	return apprbac.NewService(operatorRoleRepo, userRepo)
}

func provideMFAService(
	cfg *config,
	sessionRepo repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	userRepo repository.UserRepository,
	totpRepo repository.TOTPRepository,
	mfaCache cacheport.MFARepository,
	totpProvider securityport.TOTPProvider,
) appmfa.Manager {
	return appmfa.NewService(sessionRepo, sessionCache, userRepo, totpRepo, mfaCache, totpProvider, resolveTOTPIssuer(cfg), 10*time.Minute)
}

func providePasskeyService(
	cfg *config,
	sessionRepo repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	userRepo repository.UserRepository,
	passkeyRepo repository.PasskeyCredentialRepository,
	mfaCache cacheport.MFARepository,
	passkeyProvider securityport.PasskeyProvider,
) apppasskey.Manager {
	if !cfg.PasskeyEnabled || passkeyProvider == nil {
		return nil
	}
	return apppasskey.NewService(sessionRepo, sessionCache, userRepo, passkeyRepo, mfaCache, passkeyProvider, 10*time.Minute)
}

func provideRotationConfig(cfg *config) infracrypto.RotationConfig {
	return infracrypto.RotationConfig{
		WorkingDir:    cfg.WorkDir,
		StorageDir:    cfg.SigningKeyDir,
		KeyBits:       cfg.SigningKeyBits,
		CheckInterval: cfg.SigningKeyCheckInterval,
		RotateBefore:  cfg.SigningKeyRotateBefore,
		RetireAfter:   cfg.SigningKeyRetireAfter,
		KIDPrefix:     "kid",
	}
}

func provideKeyManager(
	ctx context.Context,
	cfg *config,
	jwkRepo *persistence.JWKKeyRepository,
	rotationConfig infracrypto.RotationConfig,
) (*infracrypto.KeyManager, error) {
	keyManager, err := infracrypto.EnsureKeyManager(ctx, jwkRepo, rotationConfig)
	if err != nil {
		return infracrypto.NewGeneratedRSAKeyManager(cfg.JWTKeyID, cfg.SigningKeyBits)
	}
	infracrypto.StartRotationLoop(jwkRepo, keyManager, rotationConfig)
	return keyManager, nil
}

func provideJWTService(keyManager *infracrypto.KeyManager) *infracrypto.JWTService {
	return infracrypto.NewJWTService(infracrypto.NewSigner(keyManager))
}

func provideTokenService(
	cfg *config,
	authCodeRepo repository.AuthorizationCodeRepository,
	clientRepo repository.ClientRepository,
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	tokenCache cacheport.TokenCacheRepository,
	deviceCodeRepo cacheport.DeviceCodeRepository,
	passwordVerifier securityport.PasswordVerifier,
	jwtService *infracrypto.JWTService,
) *apptoken.Service {
	return apptoken.NewService(
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
}

func provideDeviceService(
	clientRepo repository.ClientRepository,
	deviceCodeRepo cacheport.DeviceCodeRepository,
	sessionRepo repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
) *appdevice.Service {
	return appdevice.NewService(clientRepo, deviceCodeRepo, sessionRepo, sessionCache, 10*time.Minute, 5*time.Second)
}

func provideGrantRegistry(tokenService *apptoken.Service) *pluginregistry.GrantRegistry {
	return pluginregistry.NewGrantRegistry(
		grantauthcode.NewHandler(tokenService),
		grantrefreshtoken.NewHandler(tokenService),
		grantclientcred.NewHandler(tokenService),
		grantpassword.NewHandler(tokenService),
		grantdevicecode.NewHandler(tokenService),
	)
}

func provideClientAuthRegistry(passwordVerifier securityport.PasswordVerifier) *pluginregistry.ClientAuthRegistry {
	return pluginregistry.NewClientAuthRegistry(
		clientauthbasic.NewAuthenticator(passwordVerifier),
		clientauthpost.NewAuthenticator(passwordVerifier),
		clientauthnone.NewAuthenticator(),
	)
}

func provideClientAuthenticator(
	clientRepo repository.ClientRepository,
	clientAuthRegistry *pluginregistry.ClientAuthRegistry,
) appclientauth.Authenticator {
	return appclientauth.NewService(clientRepo, clientAuthRegistry)
}

func provideOIDCService(
	cfg *config,
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	tokenCache cacheport.TokenCacheRepository,
	jwtService *infracrypto.JWTService,
	keyManager *infracrypto.KeyManager,
) *oidc.Service {
	return oidc.NewService(
		userRepo,
		tokenRepo,
		tokenCache,
		&jwtServiceAdapter{service: jwtService},
		keyManagerAdapter{manager: keyManager},
		cfg.Issuer,
	)
}

func provideAuthMiddleware(
	cfg *config,
	tokenCache cacheport.TokenCacheRepository,
	jwtService *infracrypto.JWTService,
) *httpmiddleware.AuthMiddleware {
	return httpmiddleware.NewAuthMiddleware(&jwtMiddlewareAdapter{service: jwtService}, tokenCache, cfg.Issuer)
}

func provideAdminMiddleware(
	sessionRepo repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	userRepo repository.UserRepository,
) *httpmiddleware.SessionPermissionMiddleware {
	return httpmiddleware.NewSessionPermissionMiddleware(sessionRepo, sessionCache, userRepo)
}

func provideKeysManager(
	jwkRepo *persistence.JWKKeyRepository,
	keyManager *infracrypto.KeyManager,
	rotationConfig infracrypto.RotationConfig,
) appkeys.Manager {
	return appkeys.NewService(func(ctx context.Context) (*appkeys.RotateKeysResult, error) {
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
}

func provideRouter(
	authzService authz.Service,
	consentService appconsent.Manager,
	registerService appregister.Registrar,
	passwordResetter appregister.PasswordResetter,
	accountUnlocker appregister.AccountUnlocker,
	userRepo repository.UserRepository,
	clientCreator appclient.Creator,
	clientRedirectRegistrar appclient.Registrar,
	clientPostLogoutRedirectRegistrar appclient.PostLogoutRegistrar,
	logoutRedirectValidator appclient.LogoutRedirectValidator,
	authnService authn.Authenticator,
	federatedOIDCProvider *infraexternal.OIDCProvider,
	sessionService appsession.Manager,
	rbacService apprbac.Manager,
	keysService appkeys.Manager,
	auditRepo repository.AuditEventRepository,
	clientAuthenticator appclientauth.Authenticator,
	grantRegistry *pluginregistry.GrantRegistry,
	deviceService *appdevice.Service,
	mfaService appmfa.Manager,
	passkeyService apppasskey.Manager,
	oidcService *oidc.Service,
	authMiddleware *httpmiddleware.AuthMiddleware,
	adminMiddleware *httpmiddleware.SessionPermissionMiddleware,
) http.Handler {
	return interfacehttp.NewRouter(
		authzService,
		consentService,
		registerService,
		passwordResetter,
		accountUnlocker,
		userRepo,
		clientCreator,
		clientRedirectRegistrar,
		clientPostLogoutRedirectRegistrar,
		logoutRedirectValidator,
		authnService,
		federatedOIDCProvider != nil,
		sessionService,
		rbacService,
		keysService,
		auditRepo,
		clientAuthenticator,
		grantRegistry,
		deviceService,
		mfaService,
		passkeyService,
		oidcService,
		authMiddleware,
		adminMiddleware,
	)
}

func provideApp(router http.Handler) *App {
	return &App{Router: router}
}
