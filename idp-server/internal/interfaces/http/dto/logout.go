package dto

type LogoutRequest struct {
	ReturnTo string `json:"return_to" form:"return_to"`
}
