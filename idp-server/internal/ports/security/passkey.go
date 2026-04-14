package security

// PasskeyUser 是传给 WebAuthn/Passkey 提供者的最小用户投影。
// 它刻意不暴露完整用户模型，只保留注册/登录需要的稳定标识和展示信息。
type PasskeyUser struct {
	UserHandle  []byte
	Username    string
	DisplayName string
}

// PasskeyProvider 抽象 WebAuthn 的注册与登录流程。
// Begin* 返回给浏览器的 options 和服务端需缓存的 sessionData，
// Finish* 消费浏览器响应并产出可持久化的 credential。
type PasskeyProvider interface {
	BeginRegistration(user PasskeyUser, existingCredentialJSON []string) (optionsJSON []byte, sessionJSON []byte, err error)
	FinishRegistration(user PasskeyUser, existingCredentialJSON []string, sessionJSON []byte, responseJSON []byte) (credentialID string, credentialJSON string, err error)
	BeginLogin(user PasskeyUser, credentialJSON []string) (optionsJSON []byte, sessionJSON []byte, err error)
	FinishLogin(user PasskeyUser, credentialJSONList []string, sessionJSON []byte, responseJSON []byte) (credentialID string, credentialJSON string, err error)
}
