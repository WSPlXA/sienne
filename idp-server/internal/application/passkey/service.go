package passkey

import (
	"context"
	"strconv"
	"strings"
	"time"

	passkeydomain "idp-server/internal/domain/passkey"
	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"

	"github.com/google/uuid"
)

const passkeySetupMFAMode = "passkey_setup"

type Manager interface {
	BeginSetup(ctx context.Context, sessionID string) (*BeginSetupResult, error)
	FinishSetup(ctx context.Context, sessionID, setupID string, responseJSON []byte) (*FinishSetupResult, error)
}

type Service struct {
	sessions     repository.SessionRepository
	sessionCache cacheport.SessionCacheRepository
	users        repository.UserRepository
	passkeys     repository.PasskeyCredentialRepository
	mfaCache     cacheport.MFARepository
	passkey      securityport.PasskeyProvider
	ttl          time.Duration
	now          func() time.Time
}

func NewService(
	sessions repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	users repository.UserRepository,
	passkeys repository.PasskeyCredentialRepository,
	mfaCache cacheport.MFARepository,
	passkey securityport.PasskeyProvider,
	ttl time.Duration,
) *Service {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Service{
		sessions:     sessions,
		sessionCache: sessionCache,
		users:        users,
		passkeys:     passkeys,
		mfaCache:     mfaCache,
		passkey:      passkey,
		ttl:          ttl,
		now:          func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) BeginSetup(ctx context.Context, sessionID string) (*BeginSetupResult, error) {
	// BeginSetup 负责发起 WebAuthn 注册：
	// 读取当前用户、收集已有 credential 作为排除列表，
	// 生成浏览器侧 options 和服务端 session 数据。
	if s.passkey == nil || s.passkeys == nil || s.mfaCache == nil {
		return nil, ErrPasskeyDisabled
	}
	authUser, err := s.loadUser(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	existing, err := s.passkeys.ListByUserID(ctx, authUser.ID)
	if err != nil {
		return nil, err
	}
	optionsJSON, sessionJSON, err := s.passkey.BeginRegistration(toPasskeyUser(authUser), credentialJSONList(existing))
	if err != nil {
		return nil, err
	}

	now := s.now().UTC()
	setupID := uuid.NewString()
	expiresAt := now.Add(s.ttl)
	// WebAuthn 的 registration session 必须在服务端保存，
	// FinishRegistration 时需要用它来校验 challenge、origin 和 attestation 响应。
	if err := s.mfaCache.SaveMFAChallenge(ctx, cacheport.MFAChallengeEntry{
		ChallengeID:        setupID,
		UserID:             strconv.FormatInt(authUser.ID, 10),
		Subject:            authUser.UserUUID,
		Username:           authUser.Username,
		MFAMode:            passkeySetupMFAMode,
		PasskeySessionJSON: string(sessionJSON),
		ExpiresAt:          expiresAt,
	}, s.ttl); err != nil {
		return nil, err
	}

	return &BeginSetupResult{
		SetupID:     setupID,
		OptionsJSON: optionsJSON,
		ExpiresAt:   expiresAt,
	}, nil
}

func (s *Service) FinishSetup(ctx context.Context, sessionID, setupID string, responseJSON []byte) (*FinishSetupResult, error) {
	// FinishSetup 消费前一步缓存下来的 registration session，
	// 并把浏览器返回的 credential 结构序列化后持久化。
	if s.passkey == nil || s.passkeys == nil || s.mfaCache == nil {
		return nil, ErrPasskeyDisabled
	}
	authUser, err := s.loadUser(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	challenge, err := s.mfaCache.GetMFAChallenge(ctx, strings.TrimSpace(setupID))
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if challenge == nil || !challenge.ExpiresAt.After(now) || !strings.EqualFold(strings.TrimSpace(challenge.MFAMode), passkeySetupMFAMode) {
		return nil, ErrPasskeySetupExpired
	}
	if strings.TrimSpace(challenge.PasskeySessionJSON) == "" {
		return nil, ErrPasskeySetupExpired
	}
	if strings.TrimSpace(challenge.UserID) != strconv.FormatInt(authUser.ID, 10) {
		return nil, ErrPasskeySetupExpired
	}
	// 再次读取现有 credential 列表，避免并发注册时遗漏排除项。
	existing, err := s.passkeys.ListByUserID(ctx, authUser.ID)
	if err != nil {
		return nil, err
	}
	credentialID, credentialJSON, err := s.passkey.FinishRegistration(
		toPasskeyUser(authUser),
		credentialJSONList(existing),
		[]byte(challenge.PasskeySessionJSON),
		responseJSON,
	)
	if err != nil {
		return nil, err
	}
	if err := s.passkeys.Upsert(ctx, &passkeydomain.Model{
		UserID:         authUser.ID,
		CredentialID:   credentialID,
		CredentialJSON: credentialJSON,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		return nil, ErrPasskeyCredentialSave
	}
	if err := s.mfaCache.DeleteMFAChallenge(ctx, challenge.ChallengeID); err != nil {
		return nil, err
	}
	return &FinishSetupResult{CredentialID: credentialID}, nil
}

func (s *Service) loadUser(ctx context.Context, sessionID string) (*repositoryUser, error) {
	// 和 TOTP setup 一样，优先走缓存会话，再回退数据库，
	// 并且只接受仍处于 active 且未过期的登录态。
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, ErrLoginRequired
	}
	now := s.now().UTC()
	if s.sessionCache != nil {
		entry, err := s.sessionCache.Get(ctx, sessionID)
		if err != nil {
			return nil, err
		}
		if entry != nil && strings.EqualFold(strings.TrimSpace(entry.Status), "active") && entry.ExpiresAt.After(now) {
			userID, err := strconv.ParseInt(strings.TrimSpace(entry.UserID), 10, 64)
			if err == nil && userID > 0 {
				user, err := s.users.FindByID(ctx, userID)
				if err != nil {
					return nil, err
				}
				if user != nil {
					return &repositoryUser{
						ID:          user.ID,
						UserUUID:    user.UserUUID,
						Username:    user.Username,
						DisplayName: user.DisplayName,
					}, nil
				}
			}
		}
	}
	sessionModel, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if sessionModel == nil || sessionModel.LoggedOutAt != nil || !sessionModel.ExpiresAt.After(now) {
		return nil, ErrLoginRequired
	}
	user, err := s.users.FindByID(ctx, sessionModel.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrLoginRequired
	}
	return &repositoryUser{
		ID:          user.ID,
		UserUUID:    user.UserUUID,
		Username:    user.Username,
		DisplayName: user.DisplayName,
	}, nil
}

type repositoryUser struct {
	ID          int64
	UserUUID    string
	Username    string
	DisplayName string
}

func toPasskeyUser(user *repositoryUser) securityport.PasskeyUser {
	// Passkey user handle 优先使用稳定的 UserUUID；
	// 缺失时才退回数据库 ID，尽量避免将来用户名变化影响 credential 绑定。
	handle := []byte(strings.TrimSpace(user.UserUUID))
	if len(handle) == 0 {
		handle = []byte(strconv.FormatInt(user.ID, 10))
	}
	name := strings.TrimSpace(user.Username)
	if name == "" {
		name = strconv.FormatInt(user.ID, 10)
	}
	display := strings.TrimSpace(user.DisplayName)
	if display == "" {
		display = name
	}
	return securityport.PasskeyUser{
		UserHandle:  handle,
		Username:    name,
		DisplayName: display,
	}
}

func credentialJSONList(models []*passkeydomain.Model) []string {
	// WebAuthn 库需要的是已注册 credential 的原始 JSON 列表，
	// 这里做一次轻量过滤和整理。
	if len(models) == 0 {
		return nil
	}
	result := make([]string, 0, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		raw := strings.TrimSpace(model.CredentialJSON)
		if raw == "" {
			continue
		}
		result = append(result, raw)
	}
	return result
}
