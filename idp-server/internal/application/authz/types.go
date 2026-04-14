package authz

import "errors"

var (
	ErrInvalidRequest          = errors.New("invalid request")
	ErrUnsupportedResponseType = errors.New("unsupported response type")
	ErrInvalidClient           = errors.New("invalid client")
	ErrInvalidRedirectURI      = errors.New("invalid redirect uri")
	ErrInvalidScope            = errors.New("invalid scope")
	ErrInvalidCodeChallenge    = errors.New("invalid code challenge")
	ErrLoginRequired           = errors.New("login required")
	ErrConsentRequired         = errors.New("consent required")
)

// AuthorizationCommand 是 authorize endpoint 传给应用层的规范化授权请求。
type AuthorizationCommand struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               []string
	State               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod string
	SessionID           string
	Nonce               string
}

// AuthorizationResult 描述 authorize 请求下一步应该发生什么：
// 去登录、去 consent，或者直接回调 client。
type AuthorizationResult struct {
	RequireLogin   bool
	RequireConsent bool

	LoginRedirectURI   string
	ConsentRedirectURI string

	RedirectURI string
	Code        string
	State       string
}
