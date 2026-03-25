package dto

type RegisterRequest struct {
	Username      string `json:"username" form:"username" binding:"required"`
	Email         string `json:"email" form:"email" binding:"required"`
	DisplayName   string `json:"display_name" form:"display_name" binding:"required"`
	Password      string `json:"password" form:"password" binding:"required"`
	CSRFToken     string `json:"csrf_token" form:"csrf_token"`
	EmailVerified bool   `json:"email_verified" form:"email_verified"`
}
