package token

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	authorizationdomain "idp-server/internal/domain/authorization"
	clientdomain "idp-server/internal/domain/client"
	tokendomain "idp-server/internal/domain/token"
	userdomain "idp-server/internal/domain/user"
	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"
	pkgoauth2 "idp-server/pkg/oauth2"
	pkgoidc "idp-server/pkg/oidc"

	"github.com/google/uuid"
)

type Exchanger interface {
	Exchange(ctx context.Context, input ExchangeInput) (*ExchangeResult, error)
}

type Service struct {
	authCodes  repository.AuthorizationCodeRepository
	clients    repository.ClientRepository
	users      repository.UserRepository
	tokens     repository.TokenRepository
	tokenCache cacheport.TokenCacheRepository
	passwords  securityport.PasswordVerifier
	signer     securityport.Signer
	issuer     string
	now        func() time.Time
}

func NewService(
	authCodes repository.AuthorizationCodeRepository,
	clients repository.ClientRepository,
	users repository.UserRepository,
	tokens repository.TokenRepository,
	tokenCache cacheport.TokenCacheRepository,
	passwords securityport.PasswordVerifier,
	signer securityport.Signer,
	issuer string,
) *Service {
	return &Service{
		authCodes: authCodes,
		clients:   clients,
		users:     users,
		tokens:    tokens,
		tokenCache: tokenCache,
		passwords: passwords,
		signer:    signer,
		issuer:    issuer,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (s *Service) Exchange(ctx context.Context, input ExchangeInput) (*ExchangeResult, error) {
	switch input.GrantType {
	case pkgoauth2.GrantTypeAuthorizationCode:
		return s.exchangeAuthorizationCode(ctx, input)
	case pkgoauth2.GrantTypeRefreshToken:
		return s.exchangeRefreshToken(ctx, input)
	case pkgoauth2.GrantTypeClientCredentials:
		return s.exchangeClientCredentials(ctx, input)
	default:
		return nil, ErrUnsupportedGrantType
	}
}

func (s *Service) exchangeAuthorizationCode(ctx context.Context, input ExchangeInput) (*ExchangeResult, error) {
	if input.GrantType != pkgoauth2.GrantTypeAuthorizationCode {
		return nil, ErrUnsupportedGrantType
	}

	client, err := s.clients.FindByClientID(ctx, strings.TrimSpace(input.ClientID))
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" {
		return nil, ErrInvalidClient
	}
	if !contains(client.GrantTypes, string(pkgoauth2.GrantTypeAuthorizationCode)) {
		return nil, ErrInvalidClient
	}
	if !contains(client.RedirectURIs, input.RedirectURI) {
		return nil, ErrInvalidRedirectURI
	}
	if err := s.validateClientSecret(client.ClientSecretHash, input.ClientSecret); err != nil {
		return nil, err
	}

	code, err := s.authCodes.ConsumeByCode(ctx, input.Code, s.now())
	if err != nil {
		return nil, err
	}
	if code == nil {
		return nil, ErrInvalidCode
	}
	if code.ClientDBID != client.ID {
		return nil, ErrInvalidCode
	}
	if code.RedirectURI != input.RedirectURI {
		return nil, ErrInvalidRedirectURI
	}
	if err := validateCodeVerifier(code, input.CodeVerifier, client.RequirePKCE); err != nil {
		return nil, err
	}

	user, err := s.users.FindByID(ctx, code.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidCode
	}

	now := s.now()
	accessExpiresAt := now.Add(time.Duration(client.AccessTokenTTLSeconds) * time.Second)
	scopes := mustDecodeScopeJSON(code.ScopesJSON)
	audiences := []string{client.ClientID}
	accessToken, err := s.signer.Mint(map[string]any{
		"iss": s.issuer,
		"sub": user.UserUUID,
		"aud": audiences,
		"exp": accessExpiresAt.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"jti": uuid.NewString(),
		"cid": client.ClientID,
		"scp": scopes,
	})
	if err != nil {
		return nil, err
	}

	accessAudienceJSON, _ := json.Marshal(audiences)
	accessScopesJSON, _ := json.Marshal(scopes)
	userID := user.ID
	accessModel := &tokendomain.AccessToken{
		TokenValue:   accessToken,
		TokenSHA256:  sha256Hex(accessToken),
		ClientID:     client.ID,
		UserID:       &userID,
		Subject:      user.UserUUID,
		AudienceJSON: string(accessAudienceJSON),
		ScopesJSON:   string(accessScopesJSON),
		TokenType:    "Bearer",
		TokenFormat:  "jwt",
		IssuedAt:     now,
		ExpiresAt:    accessExpiresAt,
	}
	if err := s.tokens.CreateAccessToken(ctx, accessModel); err != nil {
		return nil, err
	}
	if s.tokenCache != nil {
		_ = s.tokenCache.SaveAccessToken(ctx, cacheport.AccessTokenCacheEntry{
			TokenSHA256:  accessModel.TokenSHA256,
			ClientID:     client.ClientID,
			UserID:       int64String(userID),
			Subject:      user.UserUUID,
			ScopesJSON:   string(accessScopesJSON),
			AudienceJSON: string(accessAudienceJSON),
			TokenType:    accessModel.TokenType,
			TokenFormat:  accessModel.TokenFormat,
			IssuedAt:     accessModel.IssuedAt,
			ExpiresAt:    accessModel.ExpiresAt,
		}, time.Until(accessExpiresAt))
	}

	result := &ExchangeResult{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(accessExpiresAt).Seconds()),
		Scope:       strings.Join(scopes, " "),
	}

	if contains(scopes, "openid") {
		idToken, err := s.mintIDToken(client, user, code, now)
		if err != nil {
			return nil, err
		}
		result.IDToken = idToken
	}

	if client.RefreshTokenTTLSeconds > 0 {
		refreshToken := uuid.NewString() + "." + uuid.NewString()
		refreshExpiresAt := now.Add(time.Duration(client.RefreshTokenTTLSeconds) * time.Second)
		refreshModel := &tokendomain.RefreshToken{
			TokenValue:  refreshToken,
			TokenSHA256: sha256Hex(refreshToken),
			ClientID:    client.ID,
			UserID:      &userID,
			Subject:     user.UserUUID,
			ScopesJSON:  string(accessScopesJSON),
			IssuedAt:    now,
			ExpiresAt:   refreshExpiresAt,
		}
		if err := s.tokens.CreateRefreshToken(ctx, refreshModel); err != nil {
			return nil, err
		}
		if s.tokenCache != nil {
			_ = s.tokenCache.SaveRefreshToken(ctx, cacheport.RefreshTokenCacheEntry{
				TokenSHA256: refreshModel.TokenSHA256,
				ClientID:    client.ClientID,
				UserID:      int64String(userID),
				Subject:     user.UserUUID,
				ScopesJSON:  string(accessScopesJSON),
				IssuedAt:    refreshModel.IssuedAt,
				ExpiresAt:   refreshModel.ExpiresAt,
			}, time.Until(refreshExpiresAt))
		}
		result.RefreshToken = refreshToken
	}

	return result, nil
}

func (s *Service) mintIDToken(client *clientdomain.Model, user *userdomain.Model, code *authorizationdomain.Model, now time.Time) (string, error) {
	idTokenTTLSeconds := client.IDTokenTTLSeconds
	if idTokenTTLSeconds <= 0 {
		idTokenTTLSeconds = client.AccessTokenTTLSeconds
		if idTokenTTLSeconds <= 0 {
			idTokenTTLSeconds = 3600
		}
	}
	idTokenExpiresAt := now.Add(time.Duration(idTokenTTLSeconds) * time.Second)

	claims := pkgoidc.Claims{
		pkgoidc.ClaimIssuer:            s.issuer,
		pkgoidc.ClaimSubject:           user.UserUUID,
		pkgoidc.ClaimAudience:          client.ClientID,
		pkgoidc.ClaimExpiration:        idTokenExpiresAt.Unix(),
		pkgoidc.ClaimIssuedAt:          now.Unix(),
		pkgoidc.ClaimAuthTime:          now.Unix(),
		pkgoidc.ClaimJWTID:             uuid.NewString(),
		pkgoidc.ClaimAuthorizedParty:   client.ClientID,
		pkgoidc.ClaimName:              user.DisplayName,
		pkgoidc.ClaimPreferredUsername: user.Username,
		pkgoidc.ClaimEmail:             user.Email,
		pkgoidc.ClaimEmailVerified:     user.EmailVerified,
	}
	if code.NonceValue != "" {
		claims[pkgoidc.ClaimNonce] = code.NonceValue
	}

	return s.signer.Mint(map[string]any(claims))
}

func (s *Service) exchangeRefreshToken(ctx context.Context, input ExchangeInput) (*ExchangeResult, error) {
	client, err := s.clients.FindByClientID(ctx, strings.TrimSpace(input.ClientID))
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" {
		return nil, ErrInvalidClient
	}
	if !contains(client.GrantTypes, string(pkgoauth2.GrantTypeRefreshToken)) {
		return nil, ErrInvalidClient
	}
	if err := s.validateClientSecret(client.ClientSecretHash, input.ClientSecret); err != nil {
		return nil, err
	}

	oldSHA := sha256Hex(input.RefreshToken)
	if s.tokenCache != nil {
		revoked, err := s.tokenCache.IsRefreshTokenRevoked(ctx, oldSHA)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, ErrInvalidRefreshToken
		}
	}

	oldRefresh, err := s.tokens.FindActiveRefreshTokenBySHA256(ctx, oldSHA)
	if err != nil {
		return nil, err
	}
	if oldRefresh == nil || oldRefresh.ClientID != client.ID {
		return nil, ErrInvalidRefreshToken
	}

	var userID int64
	if oldRefresh.UserID != nil {
		userID = *oldRefresh.UserID
	}
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidRefreshToken
	}

	now := s.now()
	scopes := mustDecodeScopeJSON(oldRefresh.ScopesJSON)
	audiences := []string{client.ClientID}
	accessExpiresAt := now.Add(time.Duration(client.AccessTokenTTLSeconds) * time.Second)
	accessToken, err := s.signer.Mint(map[string]any{
		"iss": s.issuer,
		"sub": user.UserUUID,
		"aud": audiences,
		"exp": accessExpiresAt.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"jti": uuid.NewString(),
		"cid": client.ClientID,
		"scp": scopes,
	})
	if err != nil {
		return nil, err
	}

	audienceJSON, _ := json.Marshal(audiences)
	scopesJSON, _ := json.Marshal(scopes)
	accessModel := &tokendomain.AccessToken{
		TokenValue:   accessToken,
		TokenSHA256:  sha256Hex(accessToken),
		ClientID:     client.ID,
		UserID:       oldRefresh.UserID,
		Subject:      oldRefresh.Subject,
		AudienceJSON: string(audienceJSON),
		ScopesJSON:   string(scopesJSON),
		TokenType:    "Bearer",
		TokenFormat:  "jwt",
		IssuedAt:     now,
		ExpiresAt:    accessExpiresAt,
	}
	if err := s.tokens.CreateAccessToken(ctx, accessModel); err != nil {
		return nil, err
	}
	if s.tokenCache != nil {
		_ = s.tokenCache.SaveAccessToken(ctx, cacheport.AccessTokenCacheEntry{
			TokenSHA256:  accessModel.TokenSHA256,
			ClientID:     client.ClientID,
			UserID:       int64StringPtr(oldRefresh.UserID),
			Subject:      oldRefresh.Subject,
			ScopesJSON:   string(scopesJSON),
			AudienceJSON: string(audienceJSON),
			TokenType:    accessModel.TokenType,
			TokenFormat:  accessModel.TokenFormat,
			IssuedAt:     accessModel.IssuedAt,
			ExpiresAt:    accessModel.ExpiresAt,
		}, time.Until(accessExpiresAt))
	}

	result := &ExchangeResult{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(accessExpiresAt).Seconds()),
		Scope:       strings.Join(scopes, " "),
	}

	if client.RefreshTokenTTLSeconds <= 0 {
		return result, nil
	}

	newRefreshToken := uuid.NewString() + "." + uuid.NewString()
	refreshExpiresAt := now.Add(time.Duration(client.RefreshTokenTTLSeconds) * time.Second)
	newRefresh := &tokendomain.RefreshToken{
		TokenValue:  newRefreshToken,
		TokenSHA256: sha256Hex(newRefreshToken),
		ClientID:    client.ID,
		UserID:      oldRefresh.UserID,
		Subject:     oldRefresh.Subject,
		ScopesJSON:  string(scopesJSON),
		IssuedAt:    now,
		ExpiresAt:   refreshExpiresAt,
	}
	if err := s.tokens.RotateRefreshToken(ctx, oldSHA, now, newRefresh); err != nil {
		return nil, err
	}
	if s.tokenCache != nil {
		_ = s.tokenCache.RotateRefreshToken(ctx, oldSHA, cacheport.RefreshTokenCacheEntry{
			TokenSHA256: newRefresh.TokenSHA256,
			ClientID:    client.ClientID,
			UserID:      int64StringPtr(oldRefresh.UserID),
			Subject:     oldRefresh.Subject,
			ScopesJSON:  string(scopesJSON),
			IssuedAt:    newRefresh.IssuedAt,
			ExpiresAt:   newRefresh.ExpiresAt,
		}, time.Until(refreshExpiresAt), time.Until(oldRefresh.ExpiresAt))
	}
	result.RefreshToken = newRefreshToken
	return result, nil
}

func (s *Service) exchangeClientCredentials(ctx context.Context, input ExchangeInput) (*ExchangeResult, error) {
	client, err := s.clients.FindByClientID(ctx, strings.TrimSpace(input.ClientID))
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" {
		return nil, ErrInvalidClient
	}
	if !contains(client.GrantTypes, string(pkgoauth2.GrantTypeClientCredentials)) {
		return nil, ErrInvalidClient
	}
	if err := s.validateClientSecret(client.ClientSecretHash, input.ClientSecret); err != nil {
		return nil, err
	}

	scopes := normalizeScopes(input.Scopes)
	if len(scopes) == 0 {
		scopes = append([]string(nil), client.Scopes...)
	}
	if !allContained(scopes, client.Scopes) {
		return nil, ErrInvalidScope
	}

	now := s.now()
	accessExpiresAt := now.Add(time.Duration(client.AccessTokenTTLSeconds) * time.Second)
	audiences := []string{client.ClientID}
	accessToken, err := s.signer.Mint(map[string]any{
		"iss": s.issuer,
		"sub": client.ClientID,
		"aud": audiences,
		"exp": accessExpiresAt.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"jti": uuid.NewString(),
		"cid": client.ClientID,
		"scp": scopes,
	})
	if err != nil {
		return nil, err
	}

	accessAudienceJSON, _ := json.Marshal(audiences)
	accessScopesJSON, _ := json.Marshal(scopes)
	accessModel := &tokendomain.AccessToken{
		TokenValue:   accessToken,
		TokenSHA256:  sha256Hex(accessToken),
		ClientID:     client.ID,
		UserID:       nil,
		Subject:      client.ClientID,
		AudienceJSON: string(accessAudienceJSON),
		ScopesJSON:   string(accessScopesJSON),
		TokenType:    "Bearer",
		TokenFormat:  "jwt",
		IssuedAt:     now,
		ExpiresAt:    accessExpiresAt,
	}
	if err := s.tokens.CreateAccessToken(ctx, accessModel); err != nil {
		return nil, err
	}
	if s.tokenCache != nil {
		_ = s.tokenCache.SaveAccessToken(ctx, cacheport.AccessTokenCacheEntry{
			TokenSHA256:  accessModel.TokenSHA256,
			ClientID:     client.ClientID,
			UserID:       "",
			Subject:      client.ClientID,
			ScopesJSON:   string(accessScopesJSON),
			AudienceJSON: string(accessAudienceJSON),
			TokenType:    accessModel.TokenType,
			TokenFormat:  accessModel.TokenFormat,
			IssuedAt:     accessModel.IssuedAt,
			ExpiresAt:    accessModel.ExpiresAt,
		}, time.Until(accessExpiresAt))
	}

	return &ExchangeResult{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(accessExpiresAt).Seconds()),
		Scope:       strings.Join(scopes, " "),
	}, nil
}

func (s *Service) validateClientSecret(secretHash, presentedSecret string) error {
	if strings.TrimSpace(secretHash) == "" {
		return nil
	}
	if s.passwords == nil {
		return ErrInvalidClient
	}
	if err := s.passwords.VerifyPassword(presentedSecret, secretHash); err != nil {
		return ErrInvalidClient
	}
	return nil
}

func validateCodeVerifier(code *authorizationdomain.Model, verifier string, requirePKCE bool) error {
	if code.CodeChallenge == "" {
		if requirePKCE {
			return ErrInvalidCodeVerifier
		}
		return nil
	}
	if verifier == "" {
		return ErrInvalidCodeVerifier
	}

	switch strings.ToUpper(code.CodeChallengeMethod) {
	case "", "PLAIN":
		if subtle.ConstantTimeCompare([]byte(code.CodeChallenge), []byte(verifier)) != 1 {
			return ErrInvalidCodeVerifier
		}
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(code.CodeChallenge), []byte(expected)) != 1 {
			return ErrInvalidCodeVerifier
		}
	default:
		return ErrInvalidCodeVerifier
	}

	return nil
}

func mustDecodeScopeJSON(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	var scopes []string
	if err := json.Unmarshal([]byte(raw), &scopes); err == nil {
		return scopes
	}
	return nil
}

func normalizeScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func allContained(values, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		allowedSet[value] = struct{}{}
	}

	for _, value := range values {
		if _, ok := allowedSet[value]; !ok {
			return false
		}
	}
	return true
}

func int64String(value int64) string {
	return strconv.FormatInt(value, 10)
}

func int64StringPtr(value *int64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatInt(*value, 10)
}
