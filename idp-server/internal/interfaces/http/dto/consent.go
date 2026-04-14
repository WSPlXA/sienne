package dto

// ConsentDecisionRequest 是 consent 页提交“允许/拒绝”时的输入结构。
type ConsentDecisionRequest struct {
	Action    string `json:"action" form:"action" binding:"required"`
	ReturnTo  string `json:"return_to" form:"return_to" binding:"required"`
	CSRFToken string `json:"csrf_token" form:"csrf_token"`
}
