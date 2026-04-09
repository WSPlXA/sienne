package dto

type TOTPSetupRequest struct {
	Code      string `json:"code" form:"code"`
	CSRFToken string `json:"csrf_token" form:"csrf_token"`
	ReturnTo  string `json:"return_to" form:"return_to"`
}

type LoginTOTPRequest struct {
	Action      string `json:"action" form:"action"`
	ChallengeID string `json:"challenge_id" form:"challenge_id"`
	MatchCode   string `json:"match_code" form:"match_code"`
	Code        string `json:"code" form:"code"`
	CSRFToken   string `json:"csrf_token" form:"csrf_token"`
}
