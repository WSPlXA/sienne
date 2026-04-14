package dto

// TOTPSetupRequest 是 TOTP 绑定确认页提交验证码时的输入结构。
type TOTPSetupRequest struct {
	Code      string `json:"code" form:"code"`
	CSRFToken string `json:"csrf_token" form:"csrf_token"`
	ReturnTo  string `json:"return_to" form:"return_to"`
}

// LoginTOTPRequest 是登录第二阶段页面的统一输入结构。
// 不同 action 会复用其中不同字段。
type LoginTOTPRequest struct {
	Action       string `json:"action" form:"action"`
	ChallengeID  string `json:"challenge_id" form:"challenge_id"`
	MatchCode    string `json:"match_code" form:"match_code"`
	Code         string `json:"code" form:"code"`
	ResponseJSON string `json:"response_json" form:"response_json"`
	CSRFToken    string `json:"csrf_token" form:"csrf_token"`
}
