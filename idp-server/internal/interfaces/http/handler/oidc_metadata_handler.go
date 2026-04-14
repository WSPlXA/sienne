package handler

import (
	"net/http"

	"idp-server/internal/application/oidc"

	"github.com/gin-gonic/gin"
)

type OIDCMetadataHandler struct {
	service oidc.MetadataProvider
}

func NewOIDCMetadataHandler(service oidc.MetadataProvider) *OIDCMetadataHandler {
	return &OIDCMetadataHandler{service: service}
}

func (h *OIDCMetadataHandler) Discovery(c *gin.Context) {
	// Discovery endpoint 向客户端公布本服务支持的 OIDC/OAuth 能力与端点位置。
	result, err := h.service.Discovery(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build discovery document"})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *OIDCMetadataHandler) JWKS(c *gin.Context) {
	// JWKS endpoint 对外发布当前可用于验签的公钥集合。
	result, err := h.service.JWKS(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to build jwks"})
		return
	}
	c.JSON(http.StatusOK, result)
}
