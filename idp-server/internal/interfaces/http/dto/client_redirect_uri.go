package dto

type RegisterClientRedirectURIRequest struct {
	RedirectURI  string   `json:"redirect_uri" form:"redirect_uri"`
	RedirectURIs []string `json:"redirect_uris" form:"redirect_uris"`
}
