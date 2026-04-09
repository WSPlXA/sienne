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
	appmfa "idp-server/internal/application/mfa"
	"idp-server/internal/application/oidc"
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

func NewRouter(authzService authz.Service, consentService appconsent.Manager, registerService appregister.Registrar, clientCreator appclient.Creator, clientRedirectRegistrar appclient.Registrar, clientPostLogoutRedirectRegistrar appclient.PostLogoutRegistrar, logoutRedirectValidator appclient.LogoutRedirectValidator, authnService authn.Authenticator, federatedOIDCEnabled bool, sessionService appsession.Manager, rbacService apprbac.Manager, auditRepo repository.AuditEventRepository, clientAuthenticator appclientauth.Authenticator, grantRegistry *pluginregistry.GrantRegistry, deviceService *appdevice.Service, mfaService appmfa.Manager, oidcService *oidc.Service, authMiddleware *middleware.AuthMiddleware, adminMiddleware *middleware.SessionPermissionMiddleware) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.NewLoggingMiddleware(log.Default()).Handler())
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
	loginHandler := handler.NewLoginHandler(authnService, federatedOIDCEnabled)
	loginTOTPHandler := handler.NewLoginTOTPHandler(authnService)
	loginPushHandler := handler.NewLoginPushHandler(authnService)
	logoutHandler := handler.NewLogoutHandler(sessionService)
	logoutAllHandler := handler.NewLogoutAllHandler(sessionService)
	adminUserLogoutHandler := handler.NewAdminUserLogoutHandler(sessionService, auditRepo)
	adminConsoleHandler := handler.NewAdminConsoleHandler(rbacService)
	adminActionHandler := handler.NewAdminActionHandler(
		rbacService,
		sessionService,
		clientCreator,
		clientRedirectRegistrar,
		clientPostLogoutRedirectRegistrar,
		auditRepo,
	)
	rbacHandler := handler.NewRBACHandler(rbacService, auditRepo)
	portalHandler := handler.NewPortalHandler()
	totpSetupHandler := handler.NewTOTPSetupHandler(mfaService)
	endSessionHandler := handler.NewEndSessionHandler(sessionService, logoutRedirectValidator)
	tokenHandler := handler.NewTokenHandler(clientAuthenticator, grantRegistry)
	deviceAuthorizeHandler := handler.NewDeviceAuthorizeHandler(clientAuthenticator, deviceService)
	deviceVerificationHandler := handler.NewDeviceVerificationHandler(deviceService)
	introspectionHandler := handler.NewIntrospectionHandler(clientAuthenticator, oidcService)
	userInfoHandler := handler.NewUserInfoHandler(oidcService)
	oidcMetadataHandler := handler.NewOIDCMetadataHandler(oidcService)

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

	oauth2 := router.Group("/oauth2")
	{
		oauth2.GET("/authorize", gin.WrapF(authorizeHandler.ServeHTTP))
		oauth2.GET("/jwks", oidcMetadataHandler.JWKS)
		if adminMiddleware != nil {
			oauth2.POST("/clients", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.ClientManage), clientHandler.Create)
			oauth2.POST("/clients/:client_id/redirect-uris", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.ClientManage), clientRedirectURIHandler.Handle)
			oauth2.POST("/clients/:client_id/post-logout-redirect-uris", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.ClientManage), clientPostLogoutRedirectURIHandler.Handle)
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
		admin := router.Group("/admin")
		admin.GET("", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), adminConsoleHandler.Handle)
		admin.GET("/", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), adminConsoleHandler.Handle)
		admin.GET("/workbench/support", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), portalHandler.SupportWorkbench)
		admin.GET("/workbench/oauth", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OAuthRead, rbac.ClientRead), portalHandler.OAuthWorkbench)
		admin.GET("/workbench/security", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.AuditRead, rbac.KeyRead), portalHandler.SecurityWorkbench)
		admin.GET("/rbac/roles", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), rbacHandler.ListRoles)
		admin.GET("/rbac/roles/:role_code/users", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), rbacHandler.ListUsersByRole)
		admin.GET("/rbac/usage", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.OpsRead), rbacHandler.RoleUsage)
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
		admin.POST("/actions/clients/create", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.ClientManage), adminActionHandler.CreateOAuthClient)
		admin.POST("/actions/clients/redirect-uris", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.ClientManage), adminActionHandler.RegisterClientRedirectURIs)
		admin.POST("/actions/clients/post-logout-redirect-uris", adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.ClientManage), adminActionHandler.RegisterClientPostLogoutRedirectURIs)
	}

	return router
}

func routerWantsHTML(accept string) bool {
	accept = strings.ToLower(accept)
	return accept == "" || strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}
