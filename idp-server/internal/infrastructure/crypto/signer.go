package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

var jwtEncoding = base64.RawURLEncoding

// Signer 封装了最基础的 JWT 签名与验签逻辑。
// 这里不负责 claim 语义校验，只处理 JWS 格式拼装和 RSA 签名正确性。
type Signer struct {
	keys *KeyManager
}

type verifiedToken struct {
	Header    map[string]any
	Claims    map[string]any
	Signature []byte
	Signing   string
}

func NewSigner(keys *KeyManager) *Signer {
	return &Signer{keys: keys}
}

func (s *Signer) SignJWT(claims map[string]any) (string, error) {
	// 签名始终使用当前 active key，对外表现为“最新 kid”。
	if s.keys == nil {
		return "", fmt.Errorf("key manager is required")
	}

	meta, privateKey, err := s.keys.ActiveSigningKey()
	if err != nil {
		return "", err
	}
	if meta.Alg != DefaultJWTAlg {
		return "", fmt.Errorf("unsupported signing alg %q", meta.Alg)
	}

	header := map[string]any{
		"alg": meta.Alg,
		"typ": "JWT",
		"kid": meta.KID,
	}

	// JWT 的签名对象是 base64url(header) + "." + base64url(claims)，
	// 这里严格按 JWS 紧凑序列化格式拼装 signing input。
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}

	signingInput := jwtEncoding.EncodeToString(headerJSON) + "." + jwtEncoding.EncodeToString(claimsJSON)
	hashed := sha256.Sum256([]byte(signingInput))

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signingInput + "." + jwtEncoding.EncodeToString(signature), nil
}

func (s *Signer) VerifyJWT(token string) (*verifiedToken, error) {
	// 验签流程先拆 token，再根据 header.kid 找到对应公钥，
	// 这样即使系统已经轮换到新 key，历史 token 仍可被旧公钥验证。
	if s.keys == nil {
		return nil, fmt.Errorf("key manager is required")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid jwt format")
	}

	headerBytes, err := jwtEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode jwt header: %w", err)
	}
	claimsBytes, err := jwtEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt claims: %w", err)
	}
	signature, err := jwtEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode jwt signature: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unmarshal jwt header: %w", err)
	}

	alg, _ := header["alg"].(string)
	if alg != DefaultJWTAlg {
		return nil, fmt.Errorf("unsupported jwt alg %q", alg)
	}

	kid, _ := header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("jwt kid is required")
	}

	meta, publicKey, err := s.keys.PublicKeyByKID(kid)
	if err != nil {
		return nil, err
	}
	if meta.Alg != alg {
		// kid 找到了但算法声明不一致时直接拒绝，防止算法降级或元数据错配。
		return nil, fmt.Errorf("jwt alg mismatch for kid %q", kid)
	}

	signingInput := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature); err != nil {
		return nil, fmt.Errorf("verify jwt signature: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal jwt claims: %w", err)
	}

	return &verifiedToken{
		Header:    header,
		Claims:    claims,
		Signature: signature,
		Signing:   signingInput,
	}, nil
}
