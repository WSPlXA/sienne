package http

import (
	"log"
	"net/http"

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

	"idp-server/internal/application/authz"
	"idp-server/internal/interfaces/http/handler"
	"idp-server/internal/interfaces/http/middleware"
	pluginregistry "idp-server/internal/plugins/registry"
	"idp-server/pkg/rbac"
)

func NewRouter(authzService authz.Service, consentService appconsent.Manager, registerService appregister.Registrar, clientCreator appclient.Creator, clientRedirectRegistrar appclient.Registrar, clientPostLogoutRedirectRegistrar appclient.PostLogoutRegistrar, logoutRedirectValidator appclient.LogoutRedirectValidator, authnService authn.Authenticator, federatedOIDCEnabled bool, sessionService appsession.Manager, rbacService apprbac.Manager, clientAuthenticator appclientauth.Authenticator, grantRegistry *pluginregistry.GrantRegistry, deviceService *appdevice.Service, mfaService appmfa.Manager, oidcService *oidc.Service, authMiddleware *middleware.AuthMiddleware, adminMiddleware *middleware.SessionPermissionMiddleware) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.NewLoggingMiddleware(log.Default()).Handler())

	authorizeHandler := handler.NewAuthorizationHandler(authzService)
	clientHandler := handler.NewClientHandler(clientCreator)
	consentHandler := handler.NewConsentHandler(consentService)
	registerHandler := handler.NewRegisterHandler(registerService)
	clientRedirectURIHandler := handler.NewClientRedirectURIHandler(clientRedirectRegistrar)
	clientPostLogoutRedirectURIHandler := handler.NewClientPostLogoutRedirectURIHandler(clientPostLogoutRedirectRegistrar)
	loginHandler := handler.NewLoginHandler(authnService, federatedOIDCEnabled)
	loginTOTPHandler := handler.NewLoginTOTPHandler(authnService)
	logoutHandler := handler.NewLogoutHandler(sessionService)
	logoutAllHandler := handler.NewLogoutAllHandler(sessionService)
	adminUserLogoutHandler := handler.NewAdminUserLogoutHandler(sessionService)
	rbacHandler := handler.NewRBACHandler(rbacService)
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
	router.GET("/.well-known/openid-configuration", oidcMetadataHandler.Discovery)
	router.GET("/login", loginHandler.Handle)
	router.POST("/login", loginHandler.Handle)
	router.GET("/login/totp", loginTOTPHandler.Handle)
	router.POST("/login/totp", loginTOTPHandler.Handle)
	router.GET("/mfa/totp/setup", totpSetupHandler.Handle)
	router.POST("/mfa/totp/setup", totpSetupHandler.Handle)
	router.GET("/device", deviceVerificationHandler.Handle)
	router.POST("/device", deviceVerificationHandler.Handle)
	router.GET("/connect/logout", endSessionHandler.Get)
	router.POST("/connect/logout", endSessionHandler.Post)
	router.POST("/logout", logoutHandler.Handle)
	router.POST("/logout/all", logoutAllHandler.Handle)
	router.GET("/register", registerHandler.Handle)
	router.POST("/register", registerHandler.Handle)
	router.GET("/consent", consentHandler.Handle)
	router.POST("/consent", consentHandler.Handle)

	oauth2 := router.Group("/oauth2")
	{
		oauth2.GET("/authorize", gin.WrapF(authorizeHandler.ServeHTTP))
		oauth2.GET("/jwks", oidcMetadataHandler.JWKS)
		oauth2.POST("/clients", clientHandler.Create)
		oauth2.POST("/clients/:client_id/redirect-uris", clientRedirectURIHandler.Handle)
		oauth2.POST("/clients/:client_id/post-logout-redirect-uris", clientPostLogoutRedirectURIHandler.Handle)
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
		admin.Use(adminMiddleware.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage))
		admin.GET("/rbac/roles", rbacHandler.ListRoles)
		admin.GET("/rbac/roles/:role_code/users", rbacHandler.ListUsersByRole)
		admin.GET("/rbac/usage", rbacHandler.RoleUsage)
		admin.POST("/rbac/bootstrap", adminMiddleware.RequireSessionPermissions(rbac.OpsManage), rbacHandler.Bootstrap)
		admin.POST("/rbac/roles", adminMiddleware.RequireSessionPermissions(rbac.OpsManage), rbacHandler.CreateRole)
		admin.PUT("/rbac/roles/:role_code", adminMiddleware.RequireSessionPermissions(rbac.OpsManage), rbacHandler.UpdateRole)
		admin.DELETE("/rbac/roles/:role_code", adminMiddleware.RequireSessionPermissions(rbac.OpsManage), rbacHandler.DeleteRole)
		admin.POST("/users/:user_id/role", rbacHandler.AssignRole)
		admin.POST("/users/:user_id/logout-all", adminUserLogoutHandler.Handle)
	}

	return router
}
