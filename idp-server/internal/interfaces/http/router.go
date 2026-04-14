package http

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"idp-server/internal/application/authn"
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
	"idp-server/internal/ports/repository"

	"idp-server/internal/application/authz"
	"idp-server/internal/interfaces/http/handler"
	"idp-server/internal/interfaces/http/middleware"
	pluginregistry "idp-server/internal/plugins/registry"
	"idp-server/pkg/rbac"
	"idp-server/resource"
)

func NewRouter(authzService authz.Service, consentService appconsent.Manager, registerService appregister.Registrar, passwordResetter appregister.PasswordResetter, accountUnlocker appregister.AccountUnlocker, userRepo repository.UserRepository, clientCreator appclient.Creator, clientRedirectRegistrar appclient.Registrar, clientPostLogoutRedirectRegistrar appclient.PostLogoutRegistrar, logoutRedirectValidator appclient.LogoutRedirectValidator, authnService authn.Authenticator, federatedOIDCEnabled bool, sessionService appsession.Manager, rbacService apprbac.Manager, keysService appkeys.Manager, auditRepo repository.AuditEventRepository, clientAuthenticator appclientauth.Authenticator, grantRegistry *pluginregistry.GrantRegistry, deviceService *appdevice.Service, mfaService appmfa.Manager, passkeyService apppasskey.Manager, oidcService *oidc.Service, authMiddleware *middleware.AuthMiddleware, adminMiddleware *middleware.SessionPermissionMiddleware) *gin.Engine {
	// Router 是系统所有 HTTP 能力的装配入口。
	// 这里不写业务逻辑，而是把 handler、中间件和 URL 空间组织起来，
	// 让“协议层职责”和“应用层职责”保持清晰分离。
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.NewLoggingMiddleware(log.Default()).Handler())

	// NoRoute 根据 Accept 头同时兼容浏览器和 API 客户端：
	// 浏览器拿到 HTML 页面，脚本/SDK 拿到结构化 JSON 错误。
	router.NoRoute(func(c *gin.Context) {
		if routerWantsHTML(c.GetHeader("Accept")) {
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.Status(http.StatusNotFound)
			_ = resource.NotFoundTemplate.Execute(c.Writer, gin.H{
				"Method": c.Request.Method,
				"Path":   c.Request.URL.Path,
			})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "route not found",
			"method":  c.Request.Method,
			"path":    c.Request.URL.Path,
		})
	})

	authorizeHandler := handler.NewAuthorizationHandler(authzService)
	clientHandler := handler.NewClientHandler(clientCreator)
	consentHandler := handler.NewConsentHandler(consentService)
	registerHandler := handler.NewRegisterHandler(registerService)
	clientRedirectURIHandler := handler.NewClientRedirectURIHandler(clientRedirectRegistrar)
	clientPostLogoutRedirectURIHandler := handler.NewClientPostLogoutRedirectURIHandler(clientPostLogoutRedirectRegistrar)
	loginHandler := handler.NewLoginHandler(authnService, federatedOIDCEnabled, auditRepo)
	loginTOTPHandler := handler.NewLoginTOTPHandler(authnService, auditRepo)
	loginPushHandler := handler.NewLoginPushHandler(authnService)
	logoutHandler := handler.NewLogoutHandler(sessionService)
	logoutAllHandler := handler.NewLogoutAllHandler(sessionService)
	adminUserLogoutHandler := handler.NewAdminUserLogoutHandler(sessionService, auditRepo)
	adminConsoleHandler := handler.NewAdminConsoleHandler(rbacService, userRepo)
	auditConsoleHandler := handler.NewAuditConsoleHandler(auditRepo, userRepo)
	adminUserLookupHandler := handler.NewAdminUserLookupHandler(userRepo)
	adminActionHandler := handler.NewAdminActionHandler(
		rbacService,
		sessionService,
		clientCreator,
		clientRedirectRegistrar,
		clientPostLogoutRedirectRegistrar,
		passwordResetter,
		accountUnlocker,
		keysService,
		auditRepo,
	)
	rbacHandler := handler.NewRBACHandler(rbacService, auditRepo)
	portalHandler := handler.NewPortalHandler()
	totpSetupHandler := handler.NewTOTPSetupHandler(mfaService)
	passkeySetupHandler := handler.NewPasskeySetupHandler(passkeyService)
	endSessionHandler := handler.NewEndSessionHandler(sessionService, logoutRedirectValidator)
	tokenHandler := handler.NewTokenHandler(clientAuthenticator, grantRegistry)
	deviceAuthorizeHandler := handler.NewDeviceAuthorizeHandler(clientAuthenticator, deviceService)
	deviceVerificationHandler := handler.NewDeviceVerificationHandler(deviceService)
	introspectionHandler := handler.NewIntrospectionHandler(clientAuthenticator, oidcService)
	userInfoHandler := handler.NewUserInfoHandler(oidcService)
	oidcMetadataHandler := handler.NewOIDCMetadataHandler(oidcService)

	// 顶层公共路由：健康检查、登录页、MFA 页面、登出和 OIDC 元数据。
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/", portalHandler.Home)
	router.GET("/.well-known/openid-configuration", oidcMetadataHandler.Discovery)
	router.GET("/login", loginHandler.Handle)
	router.POST("/login", loginHandler.Handle)
	router.GET("/login/totp", loginTOTPHandler.Handle)
	router.POST("/login/totp", loginTOTPHandler.Handle)
	router.GET("/mfa/push", loginPushHandler.Handle)
	router.POST("/mfa/push", loginPushHandler.Handle)
	router.GET("/mfa/passkey/setup", passkeySetupHandler.Handle)
	router.POST("/mfa/passkey/setup", passkeySetupHandler.Handle)
	router.GET("/mfa/totp/setup", totpSetupHandler.Handle)
	router.POST("/mfa/totp/setup", totpSetupHandler.Handle)
	router.GET("/device", deviceVerificationHandler.Handle)
	router.POST("/device", deviceVerificationHandler.Handle)
	router.GET("/connect/logout", endSessionHandler.Get)
	router.POST("/connect/logout", endSessionHandler.Post)
	router.POST("/logout", logoutHandler.Handle)
	router.POST("/logout/all", logoutAllHandler.Handle)
	if adminMiddleware != nil {
		router.GET("/register", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), registerHandler.Handle)
		router.POST("/register", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), registerHandler.Handle)
	} else {
		router.GET("/register", func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "register disabled: admin middleware unavailable"})
		})
		router.POST("/register", func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "register disabled: admin middleware unavailable"})
		})
	}
	router.GET("/consent", consentHandler.Handle)
	router.POST("/consent", consentHandler.Handle)

	// /oauth2 下面放协议接口，主要给 OAuth/OIDC 客户端调用。
	oauth2 := router.Group("/oauth2")
	{
		oauth2.GET("/authorize", gin.WrapF(authorizeHandler.ServeHTTP))
		oauth2.GET("/jwks", oidcMetadataHandler.JWKS)
		if adminMiddleware != nil {
			oauth2.POST("/clients", adminMiddleware.RequireSessionPermissions(rbac.ClientManage), clientHandler.Create)
			oauth2.POST("/clients/:client_id/redirect-uris", adminMiddleware.RequireSessionPermissions(rbac.ClientManage), clientRedirectURIHandler.Handle)
			oauth2.POST("/clients/:client_id/post-logout-redirect-uris", adminMiddleware.RequireSessionPermissions(rbac.ClientManage), clientPostLogoutRedirectURIHandler.Handle)
		} else {
			oauth2.POST("/clients", clientHandler.Create)
			oauth2.POST("/clients/:client_id/redirect-uris", clientRedirectURIHandler.Handle)
			oauth2.POST("/clients/:client_id/post-logout-redirect-uris", clientPostLogoutRedirectURIHandler.Handle)
		}
		oauth2.POST("/token", tokenHandler.Handle)
		oauth2.POST("/device/authorize", deviceAuthorizeHandler.Handle)
		oauth2.POST("/introspect", introspectionHandler.Handle)
		if authMiddleware != nil {
			oauth2.GET("/userinfo", authMiddleware.RequireBearerToken(), userInfoHandler.Handle)
		} else {
			oauth2.GET("/userinfo", userInfoHandler.Handle)
		}
	}

	if adminMiddleware != nil {
		// /admin 下面放运营后台入口，统一走基于会话的权限校验。
		// 这里不是单纯“是否已登录”，而是必须具备对应 RBAC 权限。
		admin := router.Group("/admin")
		admin.GET("", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), adminConsoleHandler.Handle)
		admin.GET("/", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), adminConsoleHandler.Handle)
		admin.GET("/workbench/support", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), portalHandler.SupportWorkbench)
		admin.GET("/workbench/oauth", adminMiddleware.RequireSessionPermissions(rbac.OAuthRead, rbac.ClientRead), portalHandler.OAuthWorkbench)
		admin.GET("/workbench/security", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.AuditRead, rbac.KeyRead), portalHandler.SecurityWorkbench)
		admin.GET("/audit", adminMiddleware.RequireSessionPermissions(rbac.AuditRead), auditConsoleHandler.Handle)
		admin.GET("/rbac/roles", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), rbacHandler.ListRoles)
		admin.GET("/rbac/roles/:role_code/users", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), rbacHandler.ListUsersByRole)
		admin.GET("/rbac/usage", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), rbacHandler.RoleUsage)
		admin.GET("/users/lookup-by-username", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserRead), adminUserLookupHandler.LookupByUsername)
		admin.POST("/rbac/bootstrap", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsManage), rbacHandler.Bootstrap)
		admin.POST("/rbac/roles", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsManage), rbacHandler.CreateRole)
		admin.PUT("/rbac/roles/:role_code", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsManage), rbacHandler.UpdateRole)
		admin.DELETE("/rbac/roles/:role_code", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsManage), rbacHandler.DeleteRole)
		admin.POST("/users/:user_id/role", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), rbacHandler.AssignRole)
		admin.POST("/users/:user_id/logout-all", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), adminUserLogoutHandler.Handle)
		admin.POST("/actions/rbac/bootstrap", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsManage), adminActionHandler.BootstrapRoles)
		admin.POST("/actions/rbac/roles/create", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsManage), adminActionHandler.CreateRole)
		admin.POST("/actions/rbac/roles/update", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsManage), adminActionHandler.UpdateRole)
		admin.POST("/actions/rbac/roles/delete", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsManage), adminActionHandler.DeleteRole)
		admin.POST("/actions/users/assign-role", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), adminActionHandler.AssignRole)
		admin.POST("/actions/users/logout-all", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), adminActionHandler.LogoutUser)
		admin.POST("/actions/users/change-password", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), adminActionHandler.ChangeUserPassword)
		admin.POST("/actions/users/unlock", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), adminActionHandler.UnlockUser)
		admin.POST("/actions/keys/rotate", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.KeyManage), adminActionHandler.RotateSigningKey)
		admin.POST("/actions/clients/create", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.ClientManage), adminActionHandler.CreateOAuthClient)
		admin.POST("/actions/clients/redirect-uris", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.ClientManage), adminActionHandler.RegisterClientRedirectURIs)
		admin.POST("/actions/clients/post-logout-redirect-uris", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.ClientManage), adminActionHandler.RegisterClientPostLogoutRedirectURIs)
	}

	return router
}

func routerWantsHTML(accept string) bool {
	// 浏览器在很多情况下会发 text/html 或 */*，
	// 这里用一个宽松判断让页面路由和 API 路由能共享同一个 404 入口。
	accept = strings.ToLower(accept)
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}
