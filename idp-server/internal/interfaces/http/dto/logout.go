package dto

type LogoutRequest struct {
	ReturnTo  string `json:"return_to" form:"return_to"`
	CSRFToken string `json:"csrf_token" form:"csrf_token"`
}
