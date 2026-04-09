package dto

type PasskeySetupRequest struct {
	Action       string `json:"action" form:"action"`
	SetupID      string `json:"setup_id" form:"setup_id"`
	ResponseJSON string `json:"response_json" form:"response_json"`
	CSRFToken    string `json:"csrf_token" form:"csrf_token"`
	ReturnTo     string `json:"return_to" form:"return_to"`
}
