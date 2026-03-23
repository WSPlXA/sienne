package register

import (
	"errors"
	"time"
)

var (
	ErrInvalidUsername      = errors.New("invalid username")
	ErrInvalidEmail         = errors.New("invalid email")
	ErrInvalidDisplayName   = errors.New("invalid display name")
	ErrWeakPassword         = errors.New("password does not meet policy")
	ErrUsernameAlreadyUsed  = errors.New("username already exists")
	ErrEmailAlreadyUsed     = errors.New("email already exists")
)

type RegisterInput struct {
	Username        string
	Email           string
	DisplayName     string
	Password        string
	EmailVerified   bool
	AutoActivate    bool
}

type RegisterResult struct {
	UserID        int64
	UserUUID      string
	Username      string
	Email         string
	EmailVerified bool
	DisplayName   string
	Status        string
	CreatedAt     time.Time
}
