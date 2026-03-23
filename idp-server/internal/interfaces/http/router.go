package http

import (
	"log"
	"net/http"

	"idp-server/internal/application/authn"
	appconsent "idp-server/internal/application/consent"
	"idp-server/internal/application/oidc"
	appregister "idp-server/internal/application/register"
	"github.com/gin-gonic/gin"

	"idp-server/internal/application/authz"
	apptoken "idp-server/internal/application/token"
	"idp-server/internal/interfaces/http/handler"
	"idp-server/internal/interfaces/http/middleware"
)

func NewRouter(authzService authz.Service, consentService appconsent.Manager, registerService appregister.Registrar, authnService authn.Authenticator, tokenService apptoken.Exchanger, oidcService *oidc.Service, authMiddleware *middleware.AuthMiddleware) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middleware.NewLoggingMiddleware(log.Default()).Handler())

	authorizeHandler := handler.NewAuthorizationHandler(authzService)
	consentHandler := handler.NewConsentHandler(consentService)
	registerHandler := handler.NewRegisterHandler(registerService)
	loginHandler := handler.NewLoginHandler(authnService)
	tokenHandler := handler.NewTokenHandler(tokenService)
	userInfoHandler := handler.NewUserInfoHandler(oidcService)
	oidcMetadataHandler := handler.NewOIDCMetadataHandler(oidcService)

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/.well-known/openid-configuration", oidcMetadataHandler.Discovery)
	router.GET("/login", loginHandler.Handle)
	router.POST("/login", loginHandler.Handle)
	router.GET("/register", registerHandler.Handle)
	router.POST("/register", registerHandler.Handle)
	router.GET("/consent", consentHandler.Handle)
	router.POST("/consent", consentHandler.Handle)

	oauth2 := router.Group("/oauth2")
	{
		oauth2.GET("/authorize", gin.WrapF(authorizeHandler.ServeHTTP))
		oauth2.GET("/jwks", oidcMetadataHandler.JWKS)
		oauth2.POST("/token", tokenHandler.Handle)
		if authMiddleware != nil {
			oauth2.GET("/userinfo", authMiddleware.RequireBearerToken(), userInfoHandler.Handle)
		} else {
			oauth2.GET("/userinfo", userInfoHandler.Handle)
		}
	}

	return router
}
