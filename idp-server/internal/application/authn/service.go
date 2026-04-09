package authn

import (
	"context"
	"crypto/rand"
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
}

const totpStepReplayTTL = 120 * time.Second

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
	if ratePolicy.FailureWindow <= 0 && ratePolicy.MaxFailuresPerIP == 0 && ratePolicy.MaxFailuresPerUser == 0 && ratePolicy.UserLockThreshold == 0 && ratePolicy.UserLockTTL == 0 {
		ratePolicy = DefaultRateLimitPolicy()
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
	}
}

func (s *Service) WithPasskey(passkeyRepo repository.PasskeyCredentialRepository, passkey securityport.PasskeyProvider) *Service {
	s.passkeyRepo = passkeyRepo
	s.passkey = passkey
	return s
}

func (s *Service) Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error) {
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
		passwordUser, err = s.preparePasswordAuthentication(ctx, input.Username, input.IPAddress)
		if err != nil {
			return nil, err
		}
	}

	authnResult, err := method.Authenticate(ctx, pluginport.AuthenticateInput{
		Username:    input.Username,
		Password:    input.Password,
		RedirectURI: input.RedirectURI,
		ReturnTo:    input.ReturnTo,
		State:       input.State,
		Code:        input.Code,
		Nonce:       input.Nonce,
		User:        passwordUser,
	})
	if err != nil {
		if methodType == pluginport.AuthnMethodTypePassword && errors.Is(err, ErrInvalidCredentials) {
			return nil, s.registerPasswordFailure(ctx, input.Username, input.IPAddress, passwordUser)
		}
		return nil, err
	}
	if authnResult != nil && authnResult.RedirectURI != "" && !authnResult.Authenticated {
		return &AuthenticateResult{
			RedirectURI: authnResult.RedirectURI,
		}, nil
	}
	if authnResult == nil || !authnResult.Handled || !authnResult.Authenticated {
		if methodType == pluginport.AuthnMethodTypePassword {
			return nil, s.registerPasswordFailure(ctx, input.Username, input.IPAddress, passwordUser)
		}
		return nil, ErrInvalidCredentials
	}

	user, err := s.resolveUser(ctx, authnResult)
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
	if err := s.userRepo.ResetFailedLogin(ctx, user.ID, now); err != nil {
		return nil, err
	}
	if methodType == pluginport.AuthnMethodTypePassword {
		if err := s.resetPasswordRateLimit(ctx, user.Username); err != nil {
			return nil, err
		}
	}

	if methodType == pluginport.AuthnMethodTypePassword {
		credential, err := s.lookupTOTP(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		if credential != nil {
			challengeID, err := s.createMFAChallenge(ctx, user, input)
			if err != nil {
				return nil, err
			}
			passkeyCredentialJSON, err := s.lookupPasskeyCredentialJSON(ctx, user.ID)
			if err != nil {
				return nil, err
			}
			mfaMode := MFAModeTOTPOnly
			passkeyAvailable := len(passkeyCredentialJSON) > 0 && s.passkey != nil
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
				PushCode:         buildPushMatchCode(challengeID),
			}, ErrMFARequired
		}
		if s.forceMFAEnrollment {
			result, err := s.createSession(ctx, user, methodType, input.IPAddress, input.UserAgent, authnResult.RedirectURI, input.ReturnTo, now)
			if err != nil {
				return nil, err
			}
			result.MFAEnrollmentRequired = true
			return result, ErrMFAEnrollmentRequired
		}
	}

	return s.createSession(ctx, user, methodType, input.IPAddress, input.UserAgent, authnResult.RedirectURI, input.ReturnTo, now)
}

func (s *Service) VerifyTOTP(ctx context.Context, input VerifyTOTPInput) (*AuthenticateResult, error) {
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
	if err := s.mfaCache.DeleteMFAChallenge(ctx, challenge.ChallengeID); err != nil {
		return nil, err
	}
	return s.createSession(ctx, user, pluginport.AuthnMethodTypePassword, challenge.IPAddress, challenge.UserAgent, challenge.RedirectURI, challenge.ReturnTo, now)
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

func (s *Service) resolveUser(ctx context.Context, result *pluginport.AuthenticateResult) (*userdomain.Model, error) {
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
	}

	if username := strings.TrimSpace(result.Username); username != "" {
		user, err := s.userRepo.FindByUsername(ctx, username)
		if err != nil || user != nil {
			return user, err
		}
	}

	if email := strings.TrimSpace(result.Email); email != "" {
		user, err := s.userRepo.FindByEmail(ctx, email)
		if err != nil || user != nil {
			return user, err
		}
	}

	return nil, nil
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

	if s.rateLimits != nil && s.ratePolicy.MaxFailuresPerIP > 0 && ipAddress != "" {
		failures, err := s.rateLimits.GetLoginFailByIP(ctx, ipAddress)
		if err != nil {
			return nil, err
		}
		if failures >= s.ratePolicy.MaxFailuresPerIP {
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

	if s.rateLimits != nil && s.ratePolicy.MaxFailuresPerUser > 0 && username != "" {
		failures, err := s.rateLimits.GetLoginFailByUser(ctx, username)
		if err != nil {
			return nil, err
		}
		if failures >= s.ratePolicy.MaxFailuresPerUser {
			return nil, ErrRateLimited
		}
	}

	return user, nil
}

func (s *Service) registerPasswordFailure(ctx context.Context, username, ipAddress string, user *userdomain.Model) error {
	username = strings.TrimSpace(username)
	ipAddress = strings.TrimSpace(ipAddress)

	rateLimited := false
	if s.rateLimits != nil && s.ratePolicy.FailureWindow > 0 {
		if s.ratePolicy.MaxFailuresPerUser > 0 && username != "" {
			failures, err := s.rateLimits.IncrementLoginFailByUser(ctx, username, s.ratePolicy.FailureWindow)
			if err != nil {
				return err
			}
			if failures >= s.ratePolicy.MaxFailuresPerUser {
				rateLimited = true
			}
		}
		if s.ratePolicy.MaxFailuresPerIP > 0 && ipAddress != "" {
			failures, err := s.rateLimits.IncrementLoginFailByIP(ctx, ipAddress, s.ratePolicy.FailureWindow)
			if err != nil {
				return err
			}
			if failures >= s.ratePolicy.MaxFailuresPerIP {
				rateLimited = true
			}
		}
	}

	if user == nil {
		var err error
		user, err = s.lookupUserByUsername(ctx, username)
		if err != nil {
			return err
		}
	}
	if user != nil {
		failures, err := s.userRepo.IncrementFailedLogin(ctx, user.ID)
		if err != nil {
			return err
		}
		if s.rateLimits != nil && s.ratePolicy.UserLockThreshold > 0 && int64(failures) >= s.ratePolicy.UserLockThreshold {
			if err := s.rateLimits.SetUserLock(ctx, strconv.FormatInt(user.ID, 10), s.ratePolicy.UserLockTTL); err != nil {
				return err
			}
			return ErrUserLocked
		}
	}

	if rateLimited {
		return ErrRateLimited
	}
	return ErrInvalidCredentials
}

func (s *Service) resetPasswordRateLimit(ctx context.Context, username string) error {
	if s.rateLimits == nil {
		return nil
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}
	return s.rateLimits.ResetLoginFailByUser(ctx, username)
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
	return s.mfaCache.SaveMFAChallenge(ctx, *challenge, ttlUntil(now, challenge.ExpiresAt))
}

func (s *Service) createMFAChallenge(ctx context.Context, user *userdomain.Model, input AuthenticateInput) (string, error) {
	if s.mfaCache == nil || user == nil {
		return "", ErrMFARequired
	}
	challengeID := uuid.NewString()
	pushCode := buildPushMatchCode(challengeID)
	if s.mfaTTL <= 0 {
		s.mfaTTL = 5 * time.Minute
	}
	err := s.mfaCache.SaveMFAChallenge(ctx, cache.MFAChallengeEntry{
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
	return challengeID, err
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
		}
		if err := s.sessionCache.Save(ctx, cacheEntry, s.sessionTTL); err != nil {
			return nil, err
		}
	}
	return &AuthenticateResult{
		SessionID:       sessionID,
		UserID:          user.ID,
		Subject:         user.UserUUID,
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
		if entry != nil && entry.ExpiresAt.After(now) && strings.EqualFold(strings.TrimSpace(entry.Status), "active") {
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

func buildPushMatchCode(seed string) string {
	if strings.TrimSpace(seed) == "" {
		return randomTwoDigits()
	}
	sum := 0
	for _, ch := range seed {
		sum += int(ch)
	}
	return fmt.Sprintf("%02d", sum%90+10)
}

func randomTwoDigits() string {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "42"
	}
	return fmt.Sprintf("%02d", int(b[0])%90+10)
}
