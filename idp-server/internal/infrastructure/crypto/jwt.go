package crypto

import (
	"fmt"
	"time"
)

// JWTService是一个用于处理JWT（JSON Web Token）的服务结构体。它提供了生成和验证JWT的功能。
type JWTService struct {
	signer *Signer
}

type ValidateOptions struct {
	Issuer   string
	Audience string
	Subject  string
	Now      time.Time
}

type BasicValidateOptions struct {
	Issuer string
}

func NewJWTService(signer *Signer) *JWTService {
	return &JWTService{signer: signer}
}

func (s *JWTService) Mint(claims map[string]any) (string, error) {
	if s.signer == nil {
		return "", fmt.Errorf("signer is required")
	}
	return s.signer.SignJWT(claims)
}

func (s *JWTService) ParseAndValidate(token string, opts ValidateOptions) (map[string]any, error) {
	if s.signer == nil {
		return nil, fmt.Errorf("signer is required")
	}

	verified, err := s.signer.VerifyJWT(token)
	if err != nil {
		return nil, err
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	if err := validateStringClaim(verified.Claims, "iss", opts.Issuer, false); err != nil {
		return nil, err
	}
	if err := validateAudienceClaim(verified.Claims, opts.Audience); err != nil {
		return nil, err
	}
	if err := validateStringClaim(verified.Claims, "sub", opts.Subject, false); err != nil {
		return nil, err
	}
	if err := validateUnixTimeClaim(verified.Claims, "exp", now, claimMustBeFuture); err != nil {
		return nil, err
	}
	if err := validateUnixTimeClaim(verified.Claims, "nbf", now, claimMustNotBeFuture); err != nil {
		return nil, err
	}
	if err := validateUnixTimeClaim(verified.Claims, "iat", now, claimMustNotBeFuture); err != nil {
		return nil, err
	}

	return verified.Claims, nil
}

func (s *JWTService) ParseAndValidateBasic(token string, opts BasicValidateOptions) (map[string]any, error) {
	return s.ParseAndValidate(token, ValidateOptions{
		Issuer: opts.Issuer,
	})
}

type timeClaimMode int

const (
	claimMustBeFuture timeClaimMode = iota + 1
	claimMustNotBeFuture
)

func validateStringClaim(claims map[string]any, key, expected string, required bool) error {
	if expected == "" {
		return nil
	}

	value, _ := claims[key].(string)
	if value == "" {
		if required {
			return fmt.Errorf("missing %s claim", key)
		}
		return fmt.Errorf("invalid %s claim", key)
	}
	if value != expected {
		return fmt.Errorf("unexpected %s claim", key)
	}
	return nil
}

func validateAudienceClaim(claims map[string]any, expected string) error {
	if expected == "" {
		return nil
	}

	value, ok := claims["aud"]
	if !ok {
		return fmt.Errorf("missing aud claim")
	}

	switch aud := value.(type) {
	case string:
		if aud != expected {
			return fmt.Errorf("unexpected aud claim")
		}
		return nil
	case []any:
		for _, item := range aud {
			if itemValue, ok := item.(string); ok && itemValue == expected {
				return nil
			}
		}
		return fmt.Errorf("unexpected aud claim")
	default:
		return fmt.Errorf("invalid aud claim")
	}
}

func validateUnixTimeClaim(claims map[string]any, key string, now time.Time, mode timeClaimMode) error {
	value, ok := claims[key]
	if !ok {
		if key == "nbf" || key == "iat" {
			return nil
		}
		return fmt.Errorf("missing %s claim", key)
	}

	unixValue, err := claimNumberToInt64(value)
	if err != nil {
		return fmt.Errorf("invalid %s claim", key)
	}

	claimTime := time.Unix(unixValue, 0).UTC()
	switch mode {
	case claimMustBeFuture:
		if !claimTime.After(now) {
			return fmt.Errorf("%s claim has expired", key)
		}
	case claimMustNotBeFuture:
		if claimTime.After(now) {
			return fmt.Errorf("%s claim is in the future", key)
		}
	}

	return nil
}

func claimNumberToInt64(value any) (int64, error) {
	switch v := value.(type) {
	case float64:
		return int64(v), nil
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("unsupported claim number type")
	}
}
