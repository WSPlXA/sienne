package dto

type TOTPSetupRequest struct {
	Code      string `json:"code" form:"code"`
	CSRFToken string `json:"csrf_token" form:"csrf_token"`
	ReturnTo  string `json:"return_to" form:"return_to"`
}

type LoginTOTPRequest struct {
	Code      string `json:"code" form:"code"`
	CSRFToken string `json:"csrf_token" form:"csrf_token"`
}
