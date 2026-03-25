package http

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"idp-server/internal/application/authn"
	appclient "idp-server/internal/application/client"
	appclientauth "idp-server/internal/application/clientauth"
	appconsent "idp-server/internal/application/consent"
	"idp-server/internal/application/oidc"
	appregister "idp-server/internal/application/register"
	appsession "idp-server/internal/application/session"

	"idp-server/internal/application/authz"
	"idp-server/internal/interfaces/http/handler"
	"idp-server/internal/interfaces/http/middleware"
	pluginregistry "idp-server/internal/plugins/registry"
)

func NewRouter(authzService authz.Service, consentService appconsent.Manager, registerService appregister.Registrar, clientCreator appclient.Creator, clientRedirectRegistrar appclient.Registrar, clientPostLogoutRedirectRegistrar appclient.PostLogoutRegistrar, logoutRedirectValidator appclient.LogoutRedirectValidator, authnService authn.Authenticator, federatedOIDCEnabled bool, sessionService appsession.Manager, clientAuthenticator appclientauth.Authenticator, grantRegistry *pluginregistry.GrantRegistry, oidcService *oidc.Service, authMiddleware *middleware.AuthMiddleware) *gin.Engine {
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
	logoutHandler := handler.NewLogoutHandler(sessionService)
	endSessionHandler := handler.NewEndSessionHandler(sessionService, logoutRedirectValidator)
	tokenHandler := handler.NewTokenHandler(clientAuthenticator, grantRegistry)
	introspectionHandler := handler.NewIntrospectionHandler(clientAuthenticator, oidcService)
	userInfoHandler := handler.NewUserInfoHandler(oidcService)
	oidcMetadataHandler := handler.NewOIDCMetadataHandler(oidcService)

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/.well-known/openid-configuration", oidcMetadataHandler.Discovery)
	router.GET("/login", loginHandler.Handle)
	router.POST("/login", loginHandler.Handle)
	router.GET("/connect/logout", endSessionHandler.Get)
	router.POST("/connect/logout", endSessionHandler.Post)
	router.POST("/logout", logoutHandler.Handle)
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
		oauth2.POST("/introspect", introspectionHandler.Handle)
		if authMiddleware != nil {
			oauth2.GET("/userinfo", authMiddleware.RequireBearerToken(), userInfoHandler.Handle)
		} else {
			oauth2.GET("/userinfo", userInfoHandler.Handle)
		}
	}

	return router
}
