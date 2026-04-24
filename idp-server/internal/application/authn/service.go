package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	passkeydomain "idp-server/internal/domain/passkey"
	"idp-server/internal/domain/session"
	totpdomain "idp-server/internal/domain/totp"
	userdomain "idp-server/internal/domain/user"
	pluginregistry "idp-server/internal/plugins/registry"
	"idp-server/internal/ports/cache"
	pluginport "idp-server/internal/ports/plugin"
	"idp-server/internal/ports/repository"
	securityport "idp-server/internal/ports/security"

	"github.com/google/uuid"
)

type Authenticator interface {
	Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error)
	VerifyTOTP(ctx context.Context, input VerifyTOTPInput) (*AuthenticateResult, error)
	BeginMFAPasskey(ctx context.Context, input BeginMFAPasskeyInput) (*BeginMFAPasskeyResult, error)
	VerifyMFAPasskey(ctx context.Context, input VerifyMFAPasskeyInput) (*AuthenticateResult, error)
	PollMFAChallenge(ctx context.Context, input PollMFAChallengeInput) (*PollMFAChallengeResult, error)
	DecideMFAPush(ctx context.Context, input DecideMFAPushInput) (*PollMFAChallengeResult, error)
	FinalizeMFAPush(ctx context.Context, input FinalizeMFAPushInput) (*AuthenticateResult, error)
}

// Service 负责串起登录认证的完整状态机。
// 它本身不关心 HTTP 或页面渲染，只处理：
// 1. 选择认证方式并委托给插件。
// 2. 处理密码登录的限流、锁定和失败统计。
// 3. 决定是否进入 TOTP / Passkey / Push 等 MFA 分支。
// 4. 在认证完成后落库并缓存会话。
type Service struct {
	sessionRepo        repository.SessionRepository
	sessionCache       cache.SessionCacheRepository
	rateLimits         cache.RateLimitRepository
	mfaCache           cache.MFARepository
	userRepo           repository.UserRepository
	totpRepo           repository.TOTPRepository
	passkeyRepo        repository.PasskeyCredentialRepository
	registry           *pluginregistry.AuthnRegistry
	totp               securityport.TOTPProvider
	passkey            securityport.PasskeyProvider
	sessionTTL         time.Duration
	mfaTTL             time.Duration
	forceMFAEnrollment bool
	ratePolicy         RateLimitPolicy
	now                func() time.Time
	ioPool             *workerPool
	cpuPool            *workerPool
}

type userAccountLocker interface {
	LockAccount(ctx context.Context, id int64, updatedAt time.Time) error
}

const totpStepReplayTTL = 120 * time.Second
const federatedPasswordHashPlaceholder = "!federated_oidc_only"

func NewService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	sessionCache cache.SessionCacheRepository,
	rateLimits cache.RateLimitRepository,
	mfaCache cache.MFARepository,
	registry *pluginregistry.AuthnRegistry,
	totpRepo repository.TOTPRepository,
	totp securityport.TOTPProvider,
	sessionTTL time.Duration,
	mfaTTL time.Duration,
	forceMFAEnrollment bool,
	ratePolicy RateLimitPolicy,
) *Service {
	if ratePolicy.FailureWindow <= 0 &&
		ratePolicy.MaxFailuresPerIP == 0 &&
		ratePolicy.MaxFailuresPerUser == 0 &&
		ratePolicy.UserLockThreshold == 0 &&
		ratePolicy.UserLockTTL == 0 &&
		ratePolicy.PermanentUserLockThreshold == 0 {
		ratePolicy = DefaultRateLimitPolicy()
	}
	if ratePolicy.PermanentUserLockThreshold <= 0 {
		ratePolicy.PermanentUserLockThreshold = DefaultRateLimitPolicy().PermanentUserLockThreshold
	}

	return &Service{
		sessionRepo:        sessionRepo,
		sessionCache:       sessionCache,
		rateLimits:         rateLimits,
		mfaCache:           mfaCache,
		userRepo:           userRepo,
		totpRepo:           totpRepo,
		registry:           registry,
		totp:               totp,
		sessionTTL:         sessionTTL,
		mfaTTL:             mfaTTL,
		forceMFAEnrollment: forceMFAEnrollment,
		ratePolicy:         ratePolicy,
		now: func() time.Time {
			return time.Now().UTC()
		},
		ioPool:  newIOPool(),
		cpuPool: newCPUPool(),
	}
}

func (s *Service) WithPasskey(passkeyRepo repository.PasskeyCredentialRepository, passkey securityport.PasskeyProvider) *Service {
	// Passkey 是可选能力，因此采用后装配方式。
	// 这样基础密码/TOTP 流程不依赖 WebAuthn 环境也能单独运行。
	s.passkeyRepo = passkeyRepo
	s.passkey = passkey
	return s
}

func (s *Service) Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error) {
	// Authenticate 是登录入口，它先把“凭证校验”与“登录后编排”分开：
	// 插件只负责验证身份，Service 再统一处理用户状态、MFA 和会话创建。
	if s.registry == nil {
		return nil, ErrUnsupportedMethod
	}

	methodType, err := resolveMethodType(input)
	if err != nil {
		return nil, err
	}

	method, ok := s.registry.Get(methodType)
	if !ok || method == nil {
		return nil, ErrUnsupportedMethod
	}
	var passwordUser *userdomain.Model
	if methodType == pluginport.AuthnMethodTypePassword {
		passwordUser, err = runWithPool(ctx, s.ioPool, func(execCtx context.Context) (*userdomain.Model, error) {
			return s.preparePasswordAuthentication(execCtx, input.Username, input.IPAddress)
		})
		if err != nil {
			return nil, err
		}
	}

	authnInput := pluginport.AuthenticateInput{
		Username:    input.Username,
		Password:    input.Password,
		RedirectURI: input.RedirectURI,
		ReturnTo:    input.ReturnTo,
		State:       input.State,
		Code:        input.Code,
		Nonce:       input.Nonce,
		User:        passwordUser,
	}
	authnResult, err := runWithPool(ctx, s.ioPool, func(execCtx context.Context) (*pluginport.AuthenticateResult, error) {
		if methodType == pluginport.AuthnMethodTypePassword {
			return runWithPool(execCtx, s.cpuPool, func(cpuCtx context.Context) (*pluginport.AuthenticateResult, error) {
				return method.Authenticate(cpuCtx, authnInput)
			})
		}
		return method.Authenticate(execCtx, authnInput)
	})
	if err != nil {
		if methodType == pluginport.AuthnMethodTypePassword && errors.Is(err, ErrInvalidCredentials) {
			_, failureErr := runWithPool(ctx, s.ioPool, func(execCtx context.Context) (struct{}, error) {
				return struct{}{}, s.registerPasswordFailure(execCtx, input.Username, input.IPAddress, passwordUser)
			})
			return nil, failureErr
		}
		return nil, err
	}
	if authnResult != nil && authnResult.RedirectURI != "" && !authnResult.Authenticated {
		// 某些认证插件（例如联邦登录）会先返回一个跳转地址，
		// 此时认证流程还没有完成，但请求已经被该插件“接管”。
		return &AuthenticateResult{
			RedirectURI: authnResult.RedirectURI,
		}, nil
	}
	if authnResult == nil || !authnResult.Handled || !authnResult.Authenticated {
		if methodType == pluginport.AuthnMethodTypePassword {
			_, failureErr := runWithPool(ctx, s.ioPool, func(execCtx context.Context) (struct{}, error) {
				return struct{}{}, s.registerPasswordFailure(execCtx, input.Username, input.IPAddress, passwordUser)
			})
			return nil, failureErr
		}
		return nil, ErrInvalidCredentials
	}

	user, err := runWithPool(ctx, s.ioPool, func(execCtx context.Context) (*userdomain.Model, error) {
		existing, lookupErr := s.resolveExistingUser(execCtx, authnResult)
		if lookupErr != nil || existing != nil || methodType != pluginport.AuthnMethodTypeFederatedOIDC {
			return existing, lookupErr
		}
		return s.provisionFederatedUser(execCtx, authnResult)
	})
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}
	if user.Status == "locked" {
		return nil, ErrUserLocked
	}
	if user.Status != "" && user.Status != "active" {
		return nil, ErrUserDisabled
	}

	now := s.now()
	if methodType == pluginport.AuthnMethodTypePassword {
		if err := s.resetPasswordRateLimit(ctx, user.Username, input.IPAddress); err != nil {
			return nil, err
		}
	}

	if methodType == pluginport.AuthnMethodTypePassword {
		// 密码登录成功后才检查 MFA 状态。
		// 这样可以把“第一要素成功”和“是否继续挑战第二要素”明确分层。
		credential, err := s.lookupTOTP(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		passkeyCredentialJSON, err := s.lookupPasskeyCredentialJSON(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		passkeyAvailable := len(passkeyCredentialJSON) > 0 && s.passkey != nil
		if credential != nil || passkeyAvailable {
			// 这里不直接创建 session，而是先生成一个短期 MFA challenge，
			// 把登录上下文（用户、来源 IP、重定向目标）暂存在缓存中等待二次验证。
			challengeID, pushCode, err := s.createMFAChallenge(ctx, user, input)
			if err != nil {
				return nil, err
			}
			mfaMode := MFAModeTOTPOnly
			if passkeyAvailable {
				mfaMode = MFAModePasskeyTOTPFallback
			}
			if err := s.updateMFAChallengeMode(ctx, challengeID, mfaMode); err != nil {
				return nil, err
			}
			return &AuthenticateResult{
				UserID:           user.ID,
				Subject:          user.UserUUID,
				RedirectURI:      authnResult.RedirectURI,
				ReturnTo:         input.ReturnTo,
				MFARequired:      true,
				MFAChallengeID:   challengeID,
				MFAMode:          mfaMode,
				PasskeyAvailable: passkeyAvailable,
				PushStatus:       MFAPushStatusPending,
				PushCode:         pushCode,
			}, ErrMFARequired
		}
		if s.forceMFAEnrollment {
			result, err := runWithPool(ctx, s.ioPool, func(execCtx context.Context) (*AuthenticateResult, error) {
				return s.createSession(execCtx, user, methodType, input.IPAddress, input.UserAgent, authnResult.RedirectURI, input.ReturnTo, now)
			})
			if err != nil {
				return nil, err
			}
			result.MFAEnrollmentRequired = true
			return result, ErrMFAEnrollmentRequired
		}
	}

	return runWithPool(ctx, s.ioPool, func(execCtx context.Context) (*AuthenticateResult, error) {
		return s.createSession(execCtx, user, methodType, input.IPAddress, input.UserAgent, authnResult.RedirectURI, input.ReturnTo, now)
	})
}

func (s *Service) VerifyTOTP(ctx context.Context, input VerifyTOTPInput) (*AuthenticateResult, error) {
	// VerifyTOTP 处理第二要素校验，并且额外做一步“时间窗重放保护”：
	// 同一个 TOTP step 在短时间内只能消费一次，降低中间人复用风险。
	if s.mfaCache == nil {
		return nil, ErrMFAChallengeExpired
	}
	now := s.now().UTC()
	challenge, err := s.mfaCache.GetMFAChallenge(ctx, strings.TrimSpace(input.ChallengeID))
	if err != nil {
		return nil, err
	}
	if challenge == nil || !challenge.ExpiresAt.After(now) {
		return nil, ErrMFAChallengeExpired
	}
	userID, err := strconv.ParseInt(challenge.UserID, 10, 64)
	if err != nil || userID <= 0 {
		return nil, ErrMFAChallengeExpired
	}
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrMFAChallengeExpired
	}
	credential, err := s.lookupTOTP(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if credential == nil || s.totp == nil {
		return nil, ErrInvalidTOTPCode
	}
	ok, matchedStep := s.totp.VerifyCodeWithStep(credential.Secret, input.Code, now)
	if !ok {
		return nil, ErrInvalidTOTPCode
	}
	reserved, err := s.mfaCache.ReserveTOTPStepUse(ctx, challenge.UserID, cache.TOTPPurposeLogin, matchedStep, totpStepReplayTTL)
	if err != nil {
		return nil, err
	}
	if !reserved {
		return nil, ErrTOTPCodeReused
	}
	// MFA challenge 一旦成功就立即删除，确保二次验证令牌不可重复使用。
	if err := s.mfaCache.DeleteMFAChallenge(ctx, challenge.ChallengeID); err != nil {
		return nil, err
	}
	result, err := s.createSession(ctx, user, pluginport.AuthnMethodTypePassword, challenge.IPAddress, challenge.UserAgent, challenge.RedirectURI, challenge.ReturnTo, now)
	if err != nil {
		return nil, err
	}
	if s.passkey != nil && s.passkeyRepo != nil {
		passkeyCredentialJSON, err := s.lookupPasskeyCredentialJSON(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		if len(passkeyCredentialJSON) == 0 {
			result.MFAEnrollmentRequired = true
		}
	}
	return result, nil
}

func (s *Service) BeginMFAPasskey(ctx context.Context, input BeginMFAPasskeyInput) (*BeginMFAPasskeyResult, error) {
	if s.mfaCache == nil || s.passkey == nil || s.passkeyRepo == nil {
		return nil, ErrPasskeyUnavailable
	}
	now := s.now().UTC()
	challenge, err := s.mfaCache.GetMFAChallenge(ctx, strings.TrimSpace(input.ChallengeID))
	if err != nil {
		return nil, err
	}
	if challenge == nil || !challenge.ExpiresAt.After(now) {
		return nil, ErrMFAChallengeExpired
	}
	if normalizeMFAMode(challenge.MFAMode) != MFAModePasskeyTOTPFallback {
		return nil, ErrPasskeyUnavailable
	}
	userID, err := strconv.ParseInt(strings.TrimSpace(challenge.UserID), 10, 64)
	if err != nil || userID <= 0 {
		return nil, ErrMFAChallengeExpired
	}
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != "active" {
		return nil, ErrInvalidCredentials
	}
	credentialJSON, err := s.lookupPasskeyCredentialJSON(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if len(credentialJSON) == 0 {
		return nil, ErrPasskeyUnavailable
	}
	optionsJSON, sessionJSON, err := s.passkey.BeginLogin(toPasskeyUser(user), credentialJSON)
	if err != nil {
		return nil, err
	}
	challenge.PasskeySessionJSON = string(sessionJSON)
	if err := s.mfaCache.SaveMFAChallenge(ctx, *challenge, ttlUntil(now, challenge.ExpiresAt)); err != nil {
		if errors.Is(err, cache.ErrStateVersionConflict) || errors.Is(err, cache.ErrInvalidStateTransition) {
			return nil, ErrMFAChallengeExpired
		}
		return nil, err
	}
	return &BeginMFAPasskeyResult{
		ChallengeID: challenge.ChallengeID,
		OptionsJSON: optionsJSON,
		ExpiresAt:   challenge.ExpiresAt,
	}, nil
}

func (s *Service) VerifyMFAPasskey(ctx context.Context, input VerifyMFAPasskeyInput) (*AuthenticateResult, error) {
	if s.mfaCache == nil || s.passkey == nil || s.passkeyRepo == nil {
		return nil, ErrPasskeyUnavailable
	}
	now := s.now().UTC()
	challenge, err := s.mfaCache.GetMFAChallenge(ctx, strings.TrimSpace(input.ChallengeID))
	if err != nil {
		return nil, err
	}
	if challenge == nil || !challenge.ExpiresAt.After(now) {
		return nil, ErrMFAChallengeExpired
	}
	if normalizeMFAMode(challenge.MFAMode) != MFAModePasskeyTOTPFallback {
		return nil, ErrPasskeyUnavailable
	}
	if strings.TrimSpace(challenge.PasskeySessionJSON) == "" {
		return nil, ErrPasskeySessionMissing
	}
	userID, err := strconv.ParseInt(strings.TrimSpace(challenge.UserID), 10, 64)
	if err != nil || userID <= 0 {
		return nil, ErrMFAChallengeExpired
	}
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != "active" {
		return nil, ErrInvalidCredentials
	}
	credentialJSON, err := s.lookupPasskeyCredentialJSON(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if len(credentialJSON) == 0 {
		return nil, ErrPasskeyUnavailable
	}
	credentialID, updatedCredentialJSON, err := s.passkey.FinishLogin(
		toPasskeyUser(user),
		credentialJSON,
		[]byte(challenge.PasskeySessionJSON),
		input.ResponseJSON,
	)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(credentialID) != "" && strings.TrimSpace(updatedCredentialJSON) != "" {
		lastUsedAt := now
		_ = s.passkeyRepo.Upsert(ctx, &passkeydomain.Model{
			UserID:         user.ID,
			CredentialID:   strings.TrimSpace(credentialID),
			CredentialJSON: strings.TrimSpace(updatedCredentialJSON),
			LastUsedAt:     &lastUsedAt,
			UpdatedAt:      now,
			CreatedAt:      now,
		})
	}
	if err := s.mfaCache.DeleteMFAChallenge(ctx, challenge.ChallengeID); err != nil {
		return nil, err
	}
	return s.createSession(ctx, user, pluginport.AuthnMethodTypePassword, challenge.IPAddress, challenge.UserAgent, challenge.RedirectURI, challenge.ReturnTo, now)
}

func (s *Service) PollMFAChallenge(ctx context.Context, input PollMFAChallengeInput) (*PollMFAChallengeResult, error) {
	if s.mfaCache == nil {
		return nil, ErrMFAChallengeExpired
	}
	now := s.now().UTC()
	challenge, err := s.mfaCache.GetMFAChallenge(ctx, strings.TrimSpace(input.ChallengeID))
	if err != nil {
		return nil, err
	}
	if challenge == nil || !challenge.ExpiresAt.After(now) {
		return nil, ErrMFAChallengeExpired
	}
	return &PollMFAChallengeResult{
		ChallengeID:      challenge.ChallengeID,
		MFAMode:          normalizeMFAMode(challenge.MFAMode),
		PasskeyAvailable: normalizeMFAMode(challenge.MFAMode) == MFAModePasskeyTOTPFallback,
		PushStatus:       normalizePushStatus(challenge.PushStatus),
		PushCode:         challenge.PushCode,
		ExpiresAt:        challenge.ExpiresAt,
	}, nil
}

func (s *Service) DecideMFAPush(ctx context.Context, input DecideMFAPushInput) (*PollMFAChallengeResult, error) {
	if s.mfaCache == nil {
		return nil, ErrMFAChallengeExpired
	}
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action != MFAPushStatusApproved && action != MFAPushStatusDenied {
		return nil, ErrInvalidMFAAction
	}

	now := s.now().UTC()
	challenge, err := s.mfaCache.GetMFAChallenge(ctx, strings.TrimSpace(input.ChallengeID))
	if err != nil {
		return nil, err
	}
	if challenge == nil || !challenge.ExpiresAt.After(now) {
		return nil, ErrMFAChallengeExpired
	}
	if normalizeMFAMode(challenge.MFAMode) != MFAModePushTOTPFallback {
		return nil, ErrInvalidMFAAction
	}

	approverUserID, err := s.resolveActiveSessionUserID(ctx, input.ApproverSessionID)
	if err != nil {
		return nil, err
	}
	challengeUserID, err := strconv.ParseInt(strings.TrimSpace(challenge.UserID), 10, 64)
	if err != nil || challengeUserID <= 0 {
		return nil, ErrMFAChallengeExpired
	}
	if approverUserID != challengeUserID {
		return nil, ErrMFAApproverMismatch
	}

	if action == MFAPushStatusApproved {
		if strings.TrimSpace(input.MatchCode) == "" || strings.TrimSpace(input.MatchCode) != strings.TrimSpace(challenge.PushCode) {
			return nil, ErrInvalidPushMatchCode
		}
	}

	challenge.PushStatus = action
	challenge.ApproverUserID = strconv.FormatInt(approverUserID, 10)
	challenge.DecidedAt = now
	if err := s.mfaCache.SaveMFAChallenge(ctx, *challenge, ttlUntil(now, challenge.ExpiresAt)); err != nil {
		if errors.Is(err, cache.ErrStateVersionConflict) {
			return nil, ErrMFAChallengeExpired
		}
		if errors.Is(err, cache.ErrInvalidStateTransition) {
			return nil, ErrInvalidMFAAction
		}
		return nil, err
	}

	return &PollMFAChallengeResult{
		ChallengeID: challenge.ChallengeID,
		MFAMode:     normalizeMFAMode(challenge.MFAMode),
		PushStatus:  normalizePushStatus(challenge.PushStatus),
		PushCode:    challenge.PushCode,
		ExpiresAt:   challenge.ExpiresAt,
	}, nil
}

func (s *Service) FinalizeMFAPush(ctx context.Context, input FinalizeMFAPushInput) (*AuthenticateResult, error) {
	if s.mfaCache == nil {
		return nil, ErrMFAChallengeExpired
	}
	now := s.now().UTC()
	challenge, err := s.mfaCache.GetMFAChallenge(ctx, strings.TrimSpace(input.ChallengeID))
	if err != nil {
		return nil, err
	}
	if challenge == nil || !challenge.ExpiresAt.After(now) {
		return nil, ErrMFAChallengeExpired
	}
	if normalizePushStatus(challenge.PushStatus) == MFAPushStatusDenied {
		return nil, ErrMFAPushRejected
	}
	if normalizePushStatus(challenge.PushStatus) != MFAPushStatusApproved {
		return nil, ErrMFAPushNotApproved
	}

	userID, err := strconv.ParseInt(strings.TrimSpace(challenge.UserID), 10, 64)
	if err != nil || userID <= 0 {
		return nil, ErrMFAChallengeExpired
	}
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Status != "active" {
		return nil, ErrInvalidCredentials
	}
	if err := s.mfaCache.DeleteMFAChallenge(ctx, challenge.ChallengeID); err != nil {
		return nil, err
	}

	return s.createSession(ctx, user, pluginport.AuthnMethodTypePassword, challenge.IPAddress, challenge.UserAgent, challenge.RedirectURI, challenge.ReturnTo, now)
}

func resolveMethodType(input AuthenticateInput) (pluginport.AuthnMethodType, error) {
	method := pluginport.AuthnMethodType(strings.ToLower(strings.TrimSpace(input.Method)))
	if method != "" {
		switch method {
		case pluginport.AuthnMethodTypePassword, pluginport.AuthnMethodTypeFederatedOIDC:
			return method, nil
		default:
			return "", ErrUnsupportedMethod
		}
	}

	if strings.TrimSpace(input.Username) != "" || input.Password != "" {
		return pluginport.AuthnMethodTypePassword, nil
	}
	if strings.TrimSpace(input.Code) != "" || strings.TrimSpace(input.State) != "" || strings.TrimSpace(input.Nonce) != "" {
		return pluginport.AuthnMethodTypeFederatedOIDC, nil
	}

	return pluginport.AuthnMethodTypePassword, nil
}

func (s *Service) resolveExistingUser(ctx context.Context, result *pluginport.AuthenticateResult) (*userdomain.Model, error) {
	if result == nil {
		return nil, nil
	}
	if result.UserID > 0 {
		return &userdomain.Model{
			ID:          result.UserID,
			UserUUID:    strings.TrimSpace(result.Subject),
			Username:    strings.TrimSpace(result.Username),
			Email:       strings.TrimSpace(result.Email),
			DisplayName: strings.TrimSpace(result.DisplayName),
			Status:      strings.TrimSpace(result.UserStatus),
		}, nil
	}

	if subject := strings.TrimSpace(result.Subject); subject != "" {
		user, err := s.userRepo.FindByUserUUID(ctx, subject)
		if err != nil || user != nil {
			return user, err
		}
		federatedUUID := federatedSubjectUserUUID(result.IdentityProvider, subject)
		if federatedUUID != "" && federatedUUID != subject {
			user, err = s.userRepo.FindByUserUUID(ctx, federatedUUID)
			if err != nil || user != nil {
				return user, err
			}
		}
	}

	if username := strings.TrimSpace(result.Username); username != "" {
		user, err := s.userRepo.FindByUsername(ctx, username)
		if err != nil || user != nil {
			return user, err
		}
	}

	if email := normalizeFederatedEmail(result.Email); email != "" {
		user, err := s.userRepo.FindByEmail(ctx, email)
		if err != nil || user != nil {
			return user, err
		}
	}

	return nil, nil
}

func (s *Service) provisionFederatedUser(ctx context.Context, result *pluginport.AuthenticateResult) (*userdomain.Model, error) {
	// 联邦首登自动建号：优先用上游 subject 做稳定映射，再补本地用户名和邮箱。
	if result == nil || s.userRepo == nil {
		return nil, nil
	}
	subject := strings.TrimSpace(result.Subject)
	if subject == "" {
		return nil, nil
	}
	userUUID := federatedSubjectUserUUID(result.IdentityProvider, subject)
	if userUUID == "" {
		userUUID = uuid.NewString()
	}

	username, err := s.allocateFederatedUsername(ctx, result, userUUID)
	if err != nil {
		return nil, err
	}
	email := normalizeFederatedEmail(result.Email)
	if email == "" {
		email = userUUID + "@federated.local"
	}
	displayName := strings.TrimSpace(result.DisplayName)
	if displayName == "" {
		displayName = username
	}
	now := s.now().UTC()
	model := &userdomain.Model{
		UserUUID:         userUUID,
		Username:         username,
		Email:            email,
		EmailVerified:    email != "",
		DisplayName:      displayName,
		PasswordHash:     federatedPasswordHashPlaceholder,
		Status:           "active",
		FailedLoginCount: 0,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if err := s.userRepo.Create(ctx, model); err != nil {
		// 并发首登时可能发生唯一键冲突，回查一次已创建用户即可收敛。
		existing, lookupErr := s.resolveExistingUser(ctx, result)
		if lookupErr == nil && existing != nil {
			return existing, nil
		}
		return nil, err
	}
	return model, nil
}

func (s *Service) allocateFederatedUsername(ctx context.Context, result *pluginport.AuthenticateResult, userUUID string) (string, error) {
	base := sanitizeFederatedUsername(candidateFederatedUsername(result, userUUID))
	if base == "" {
		base = "oidc_user"
	}
	base = trimUsernameTo(base, 26)
	for i := 0; i < 100; i++ {
		candidate := base
		if i > 0 {
			suffix := fmt.Sprintf("_%02d", i)
			candidate = trimUsernameTo(base, 32-len(suffix)) + suffix
		}
		user, err := s.userRepo.FindByUsername(ctx, candidate)
		if err != nil {
			return "", err
		}
		if user == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("allocate federated username exhausted")
}

func candidateFederatedUsername(result *pluginport.AuthenticateResult, userUUID string) string {
	if result != nil {
		if value := strings.TrimSpace(result.Username); value != "" {
			return value
		}
		if email := normalizeFederatedEmail(result.Email); email != "" {
			if idx := strings.IndexByte(email, '@'); idx > 0 {
				return email[:idx]
			}
			return email
		}
		if value := strings.TrimSpace(result.DisplayName); value != "" {
			return value
		}
		if subject := strings.TrimSpace(result.Subject); subject != "" {
			return "oidc_" + shortStableID(subject)
		}
	}
	if strings.TrimSpace(userUUID) != "" {
		return "oidc_" + strings.ReplaceAll(strings.TrimSpace(userUUID), "-", "")
	}
	return "oidc_user"
}

func federatedSubjectUserUUID(identityProvider, subject string) string {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return ""
	}
	namespaced := strings.TrimSpace(identityProvider) + "|" + subject
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(namespaced)).String()
}

func shortStableID(value string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:6])
}

func normalizeFederatedEmail(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if strings.Contains(value, " ") || !strings.Contains(value, "@") {
		return ""
	}
	return value
}

func sanitizeFederatedUsername(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 32 {
			break
		}
	}
	out := strings.Trim(b.String(), "._-")
	for len(out) < 3 {
		out += "x"
	}
	return trimUsernameTo(out, 32)
}

func trimUsernameTo(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func sessionAuthContext(methodType pluginport.AuthnMethodType) (string, string) {
	switch methodType {
	case pluginport.AuthnMethodTypeFederatedOIDC:
		return "urn:idp:acr:federated_oidc", `["federated_oidc"]`
	default:
		return "urn:idp:acr:pwd", `["pwd"]`
	}
}

func (s *Service) preparePasswordAuthentication(ctx context.Context, username, ipAddress string) (*userdomain.Model, error) {
	username = strings.TrimSpace(username)
	ipAddress = strings.TrimSpace(ipAddress)

	if s.rateLimits != nil && ipAddress != "" {
		locked, err := s.rateLimits.IsIPLocked(ctx, ipAddress)
		if err != nil {
			return nil, err
		}
		if locked {
			return nil, ErrRateLimited
		}
	}

	user, err := s.lookupUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if user != nil && s.rateLimits != nil {
		locked, err := s.rateLimits.IsUserLocked(ctx, strconv.FormatInt(user.ID, 10))
		if err != nil {
			return nil, err
		}
		if locked {
			return nil, ErrUserLocked
		}
	}

	return user, nil
}

func (s *Service) registerPasswordFailure(ctx context.Context, username, ipAddress string, user *userdomain.Model) error {
	username = strings.TrimSpace(username)
	ipAddress = strings.TrimSpace(ipAddress)

	if s.rateLimits == nil {
		return ErrInvalidCredentials
	}

	userID := ""
	if user != nil && user.ID > 0 {
		userID = strconv.FormatInt(user.ID, 10)
	}

	if s.ratePolicy.FailureWindow > 0 && s.ratePolicy.MaxFailuresPerUser > 0 && username != "" {
		result, err := s.rateLimits.IncrementLoginFailByUser(
			ctx,
			username,
			userID,
			s.ratePolicy.FailureWindow,
			s.ratePolicy.UserLockThreshold,
			s.ratePolicy.UserLockTTL,
		)
		if err != nil {
			return err
		}
		if result != nil && result.Locked {
			return ErrUserLocked
		}
	}

	if s.ratePolicy.FailureWindow > 0 && s.ratePolicy.MaxFailuresPerIP > 0 && ipAddress != "" {
		result, err := s.rateLimits.IncrementLoginFailByIP(
			ctx,
			ipAddress,
			s.ratePolicy.FailureWindow,
			s.ratePolicy.MaxFailuresPerIP,
			s.ratePolicy.UserLockTTL,
		)
		if err != nil {
			return err
		}
		if result != nil && result.Locked {
			return ErrRateLimited
		}
	}

	if userID != "" && username != "" && s.ratePolicy.PermanentUserLockThreshold > 0 {
		result, err := s.rateLimits.IncrementBlacklistByUser(ctx, username, userID, s.ratePolicy.PermanentUserLockThreshold)
		if err != nil {
			return err
		}
		if result != nil && result.Locked {
			locker, ok := s.userRepo.(userAccountLocker)
			if !ok {
				_ = s.rateLimits.ClearUserLock(ctx, userID)
				return fmt.Errorf("user lock is not supported by repository")
			}
			if user == nil {
				_ = s.rateLimits.ClearUserLock(ctx, userID)
				return fmt.Errorf("missing user model for lock persistence")
			}
			if err := locker.LockAccount(ctx, user.ID, s.now()); err != nil {
				_ = s.rateLimits.ClearUserLock(ctx, userID)
				return err
			}
			return ErrUserLocked
		}
	}

	return ErrInvalidCredentials
}

func (s *Service) resetPasswordRateLimit(ctx context.Context, username, ipAddress string) error {
	if s.rateLimits == nil {
		return nil
	}
	username = strings.TrimSpace(username)
	if username != "" {
		if err := s.rateLimits.ResetLoginFailByUser(ctx, username); err != nil {
			return err
		}
		if err := s.rateLimits.ResetBlacklistByUser(ctx, username); err != nil {
			return err
		}
	}
	ipAddress = strings.TrimSpace(ipAddress)
	if ipAddress != "" {
		if err := s.rateLimits.ResetLoginFailByIP(ctx, ipAddress); err != nil {
			return err
		}
		if err := s.rateLimits.ClearIPLock(ctx, ipAddress); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) lookupUserByUsername(ctx context.Context, username string) (*userdomain.Model, error) {
	username = strings.TrimSpace(username)
	if username == "" || s.userRepo == nil {
		return nil, nil
	}
	return s.userRepo.FindByUsername(ctx, username)
}

func (s *Service) lookupTOTP(ctx context.Context, userID int64) (*totpdomain.Model, error) {
	if s.totpRepo == nil || userID <= 0 {
		return nil, nil
	}
	return s.totpRepo.FindByUserID(ctx, userID)
}

func (s *Service) lookupPasskeyCredentialJSON(ctx context.Context, userID int64) ([]string, error) {
	if s.passkeyRepo == nil || userID <= 0 {
		return nil, nil
	}
	credentials, err := s.passkeyRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(credentials) == 0 {
		return nil, nil
	}
	result := make([]string, 0, len(credentials))
	for _, credential := range credentials {
		if credential == nil {
			continue
		}
		raw := strings.TrimSpace(credential.CredentialJSON)
		if raw == "" {
			continue
		}
		result = append(result, raw)
	}
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func (s *Service) updateMFAChallengeMode(ctx context.Context, challengeID, mode string) error {
	if s.mfaCache == nil {
		return ErrMFAChallengeExpired
	}
	challengeID = strings.TrimSpace(challengeID)
	if challengeID == "" {
		return ErrMFAChallengeExpired
	}
	now := s.now().UTC()
	challenge, err := s.mfaCache.GetMFAChallenge(ctx, challengeID)
	if err != nil {
		return err
	}
	if challenge == nil || !challenge.ExpiresAt.After(now) {
		return ErrMFAChallengeExpired
	}
	challenge.MFAMode = normalizeMFAMode(mode)
	if err := s.mfaCache.SaveMFAChallenge(ctx, *challenge, ttlUntil(now, challenge.ExpiresAt)); err != nil {
		if errors.Is(err, cache.ErrStateVersionConflict) || errors.Is(err, cache.ErrInvalidStateTransition) {
			return ErrMFAChallengeExpired
		}
		return err
	}
	return nil
}

func (s *Service) createMFAChallenge(ctx context.Context, user *userdomain.Model, input AuthenticateInput) (string, string, error) {
	if s.mfaCache == nil || user == nil {
		return "", "", ErrMFARequired
	}
	challengeID := uuid.NewString()
	pushCode, err := buildPushMatchCode()
	if err != nil {
		return "", "", err
	}
	if s.mfaTTL <= 0 {
		s.mfaTTL = 5 * time.Minute
	}
	err = s.mfaCache.SaveMFAChallenge(ctx, cache.MFAChallengeEntry{
		ChallengeID: challengeID,
		UserID:      strconv.FormatInt(user.ID, 10),
		Subject:     user.UserUUID,
		Username:    user.Username,
		IPAddress:   input.IPAddress,
		UserAgent:   input.UserAgent,
		ReturnTo:    input.ReturnTo,
		RedirectURI: input.RedirectURI,
		MFAMode:     MFAModeTOTPOnly,
		PushStatus:  MFAPushStatusPending,
		PushCode:    pushCode,
		ExpiresAt:   s.now().Add(s.mfaTTL),
	}, s.mfaTTL)
	if errors.Is(err, cache.ErrStateVersionConflict) || errors.Is(err, cache.ErrInvalidStateTransition) {
		return "", "", ErrMFARequired
	}
	return challengeID, pushCode, err
}

func (s *Service) createSession(ctx context.Context, user *userdomain.Model, methodType pluginport.AuthnMethodType, ipAddress, userAgent, redirectURI, returnTo string, now time.Time) (*AuthenticateResult, error) {
	sessionID := uuid.NewString()
	expiresAt := now.Add(s.sessionTTL)
	acr, amrJSON := sessionAuthContext(methodType)
	if strings.Contains(amrJSON, `"pwd"`) {
		credential, err := s.lookupTOTP(ctx, user.ID)
		if err == nil && credential != nil {
			acr = "urn:idp:acr:mfa"
			amrJSON = `["pwd","otp"]`
		}
	}
	model := &session.Model{
		SessionID:       sessionID,
		UserID:          user.ID,
		Subject:         user.UserUUID,
		ACR:             acr,
		AMRJSON:         amrJSON,
		IPAddress:       ipAddress,
		UserAgent:       userAgent,
		AuthenticatedAt: now,
		ExpiresAt:       expiresAt,
	}
	if err := s.sessionRepo.Create(ctx, model); err != nil {
		return nil, err
	}
	if s.sessionCache != nil {
		cacheEntry := cache.SessionCacheEntry{
			SessionID:       sessionID,
			UserID:          strconv.FormatInt(user.ID, 10),
			Subject:         user.UserUUID,
			ACR:             model.ACR,
			AMRJSON:         model.AMRJSON,
			IPAddress:       ipAddress,
			UserAgent:       userAgent,
			AuthenticatedAt: now,
			ExpiresAt:       expiresAt,
			Status:          "active",
			StateMask:       cache.SessionStateActive,
		}
		if err := s.sessionCache.Save(ctx, cacheEntry, s.sessionTTL); err != nil {
			return nil, err
		}
	}
	return &AuthenticateResult{
		SessionID:       sessionID,
		UserID:          user.ID,
		Subject:         user.UserUUID,
		RoleCode:        user.RoleCode,
		RedirectURI:     redirectURI,
		ReturnTo:        returnTo,
		AuthenticatedAt: now,
		ExpiresAt:       expiresAt,
	}, nil
}

func (s *Service) resolveActiveSessionUserID(ctx context.Context, sessionID string) (int64, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return 0, ErrMFAApproverMismatch
	}
	now := s.now().UTC()
	if s.sessionCache != nil {
		entry, err := s.sessionCache.Get(ctx, sessionID)
		if err != nil {
			return 0, err
		}
		if cache.IsSessionEntryActive(entry, now) {
			userID, err := strconv.ParseInt(strings.TrimSpace(entry.UserID), 10, 64)
			if err == nil && userID > 0 {
				return userID, nil
			}
		}
	}
	sessionModel, err := s.sessionRepo.FindBySessionID(ctx, sessionID)
	if err != nil {
		return 0, err
	}
	if sessionModel == nil || sessionModel.LoggedOutAt != nil || !sessionModel.ExpiresAt.After(now) {
		return 0, ErrMFAApproverMismatch
	}
	return sessionModel.UserID, nil
}

func normalizeMFAMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case MFAModePasskeyTOTPFallback:
		return MFAModePasskeyTOTPFallback
	case MFAModePushTOTPFallback:
		return MFAModePushTOTPFallback
	default:
		return MFAModeTOTPOnly
	}
}

func toPasskeyUser(user *userdomain.Model) securityport.PasskeyUser {
	if user == nil {
		return securityport.PasskeyUser{}
	}
	handle := []byte(strings.TrimSpace(user.UserUUID))
	if len(handle) == 0 && user.ID > 0 {
		handle = []byte(strconv.FormatInt(user.ID, 10))
	}
	username := strings.TrimSpace(user.Username)
	if username == "" && user.ID > 0 {
		username = strconv.FormatInt(user.ID, 10)
	}
	displayName := strings.TrimSpace(user.DisplayName)
	if displayName == "" {
		displayName = username
	}
	return securityport.PasskeyUser{
		UserHandle:  handle,
		Username:    username,
		DisplayName: displayName,
	}
}

func normalizePushStatus(status string) string {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case MFAPushStatusApproved:
		return MFAPushStatusApproved
	case MFAPushStatusDenied:
		return MFAPushStatusDenied
	default:
		return MFAPushStatusPending
	}
}

func ttlUntil(now, expiresAt time.Time) time.Duration {
	ttl := expiresAt.Sub(now)
	if ttl <= 0 {
		return time.Second
	}
	return ttl
}

func buildPushMatchCode() (string, error) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate push match code: %w", err)
	}
	return fmt.Sprintf("%02d", int(b[0])%90+10), nil
}
