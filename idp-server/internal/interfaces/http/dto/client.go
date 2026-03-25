package dto

type CreateClientRequest struct {
	ClientID                string   `json:"client_id" form:"client_id" binding:"required"`
	ClientName              string   `json:"client_name" form:"client_name" binding:"required"`
	ClientSecret            string   `json:"client_secret" form:"client_secret"`
	ClientType              string   `json:"client_type" form:"client_type"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" form:"token_endpoint_auth_method"`
	RequirePKCE             *bool    `json:"require_pkce" form:"require_pkce"`
	RequireConsent          *bool    `json:"require_consent" form:"require_consent"`
	AccessTokenTTLSeconds   int      `json:"access_token_ttl_seconds" form:"access_token_ttl_seconds"`
	RefreshTokenTTLSeconds  int      `json:"refresh_token_ttl_seconds" form:"refresh_token_ttl_seconds"`
	IDTokenTTLSeconds       int      `json:"id_token_ttl_seconds" form:"id_token_ttl_seconds"`
	GrantTypes              []string `json:"grant_types" form:"grant_types" binding:"required"`
	Scopes                  []string `json:"scopes" form:"scopes" binding:"required"`
	RedirectURIs            []string `json:"redirect_uris" form:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris" form:"post_logout_redirect_uris"`
	Status                  string   `json:"status" form:"status"`
}
