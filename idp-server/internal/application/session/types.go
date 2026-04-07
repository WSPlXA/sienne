package session

type LogoutInput struct {
	SessionID string
}

type LogoutResult struct {
	SessionID string
	UserID    string
}

type LogoutAllInput struct {
	SessionID string
}

type LogoutAllResult struct {
	SessionID            string
	UserID               string
	RevokedSessionCount  int
	RevokedAccessTokens  int
	RevokedRefreshTokens int
}

type AdminLogoutUserInput struct {
	UserID int64
}
