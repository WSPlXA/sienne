package security

type PasskeyUser struct {
	UserHandle  []byte
	Username    string
	DisplayName string
}

type PasskeyProvider interface {
	BeginRegistration(user PasskeyUser, existingCredentialJSON []string) (optionsJSON []byte, sessionJSON []byte, err error)
	FinishRegistration(user PasskeyUser, existingCredentialJSON []string, sessionJSON []byte, responseJSON []byte) (credentialID string, credentialJSON string, err error)
	BeginLogin(user PasskeyUser, credentialJSON []string) (optionsJSON []byte, sessionJSON []byte, err error)
	FinishLogin(user PasskeyUser, credentialJSONList []string, sessionJSON []byte, responseJSON []byte) (credentialID string, credentialJSON string, err error)
}
