package security

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	securityport "idp-server/internal/ports/security"
)

type PasskeyProvider struct {
	webauthn *webauthnlib.WebAuthn
}

func NewPasskeyProvider(rpID, rpDisplayName string, rpOrigins []string) (*PasskeyProvider, error) {
	// RP 配置是 WebAuthn 成败的基础：
	// rpID、origin 和浏览器当前访问域名必须匹配，否则注册/登录都会失败。
	rpID = strings.TrimSpace(rpID)
	if rpID == "" {
		return nil, fmt.Errorf("passkey rpid is required")
	}
	filteredOrigins := make([]string, 0, len(rpOrigins))
	for _, origin := range rpOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			filteredOrigins = append(filteredOrigins, origin)
		}
	}
	if len(filteredOrigins) == 0 {
		return nil, fmt.Errorf("passkey rp origins are required")
	}
	if strings.TrimSpace(rpDisplayName) == "" {
		rpDisplayName = "IDP Server"
	}
	instance, err := webauthnlib.New(&webauthnlib.Config{
		RPID:          rpID,
		RPDisplayName: rpDisplayName,
		RPOrigins:     filteredOrigins,
	})
	if err != nil {
		return nil, err
	}
	return &PasskeyProvider{webauthn: instance}, nil
}

func (p *PasskeyProvider) BeginRegistration(user securityport.PasskeyUser, existingCredentialJSON []string) ([]byte, []byte, error) {
	// BeginRegistration 产出两份数据：
	// 1. 给浏览器的 options；
	// 2. 服务端需要缓存的 sessionData。
	adapter, err := newPasskeyUserAdapter(user, existingCredentialJSON)
	if err != nil {
		return nil, nil, err
	}
	options, session, err := p.webauthn.BeginRegistration(adapter)
	if err != nil {
		return nil, nil, err
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, nil, err
	}
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return optionsJSON, sessionJSON, nil
}

func (p *PasskeyProvider) FinishRegistration(user securityport.PasskeyUser, existingCredentialJSON []string, sessionJSON []byte, responseJSON []byte) (string, string, error) {
	// FinishRegistration 会校验浏览器回传的 attestation/assertion 是否与 sessionData 匹配，
	// 成功后把 credential 序列化，供后续登录时再次交给 WebAuthn 库。
	adapter, err := newPasskeyUserAdapter(user, existingCredentialJSON)
	if err != nil {
		return "", "", err
	}
	var session webauthnlib.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return "", "", err
	}
	request, err := buildWebAuthnRequest(responseJSON)
	if err != nil {
		return "", "", err
	}
	credential, err := p.webauthn.FinishRegistration(adapter, session, request)
	if err != nil {
		return "", "", err
	}
	serialized, err := json.Marshal(credential)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(credential.ID), string(serialized), nil
}

func (p *PasskeyProvider) BeginLogin(user securityport.PasskeyUser, credentialJSON []string) ([]byte, []byte, error) {
	// 登录阶段和注册阶段类似，也是一份浏览器 options + 一份服务端 sessionData。
	adapter, err := newPasskeyUserAdapter(user, credentialJSON)
	if err != nil {
		return nil, nil, err
	}
	options, session, err := p.webauthn.BeginLogin(adapter)
	if err != nil {
		return nil, nil, err
	}
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, nil, err
	}
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, nil, err
	}
	return optionsJSON, sessionJSON, nil
}

func (p *PasskeyProvider) FinishLogin(user securityport.PasskeyUser, credentialJSON []string, sessionJSON []byte, responseJSON []byte) (string, string, error) {
	// FinishLogin 返回 credentialID 和最新 credential JSON，
	// 上层可以用后者更新 sign count 等元数据。
	adapter, err := newPasskeyUserAdapter(user, credentialJSON)
	if err != nil {
		return "", "", err
	}
	var session webauthnlib.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return "", "", err
	}
	request, err := buildWebAuthnRequest(responseJSON)
	if err != nil {
		return "", "", err
	}
	credential, err := p.webauthn.FinishLogin(adapter, session, request)
	if err != nil {
		return "", "", err
	}
	serialized, err := json.Marshal(credential)
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(credential.ID), string(serialized), nil
}

type passkeyUserAdapter struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthnlib.Credential
}

func newPasskeyUserAdapter(user securityport.PasskeyUser, credentialJSON []string) (*passkeyUserAdapter, error) {
	// WebAuthn 库要求实现自己的 User 接口，这里把仓储/应用层用户模型适配过去。
	id := append([]byte(nil), user.UserHandle...)
	if len(id) == 0 {
		return nil, fmt.Errorf("passkey user handle is required")
	}
	credentials := make([]webauthnlib.Credential, 0, len(credentialJSON))
	for _, raw := range credentialJSON {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var credential webauthnlib.Credential
		if err := json.Unmarshal([]byte(raw), &credential); err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	name := strings.TrimSpace(user.Username)
	if name == "" {
		name = base64.RawURLEncoding.EncodeToString(id)
	}
	displayName := strings.TrimSpace(user.DisplayName)
	if displayName == "" {
		displayName = name
	}
	return &passkeyUserAdapter{
		id:          id,
		name:        name,
		displayName: displayName,
		credentials: credentials,
	}, nil
}

func (u *passkeyUserAdapter) WebAuthnID() []byte {
	return u.id
}

func (u *passkeyUserAdapter) WebAuthnName() string {
	return u.name
}

func (u *passkeyUserAdapter) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *passkeyUserAdapter) WebAuthnCredentials() []webauthnlib.Credential {
	return u.credentials
}

func buildWebAuthnRequest(responseJSON []byte) (*http.Request, error) {
	// go-webauthn 直接消费 http.Request，这里构造一个最小 POST 请求作为适配层。
	request, err := http.NewRequest(http.MethodPost, "/webauthn", bytes.NewReader(responseJSON))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	return request, nil
}
