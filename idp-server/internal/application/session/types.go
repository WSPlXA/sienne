package session

type LogoutInput struct {
	SessionID string
}

type LogoutResult struct {
	SessionID string
	UserID    string
}
