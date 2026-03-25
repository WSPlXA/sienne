package authn

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"idp-server/internal/domain/session"
	userdomain "idp-server/internal/domain/user"
	pluginregistry "idp-server/internal/plugins/registry"
	"idp-server/internal/ports/cache"
	pluginport "idp-server/internal/ports/plugin"
	"idp-server/internal/ports/repository"

	"github.com/google/uuid"
)

type Authenticator interface {
	Authenticate(ctx context.Context, input AuthenticateInput) (*AuthenticateResult, error)
}

type Service struct {
	sessionRepo  repository.SessionRepository
	sessionCache cache.SessionCacheRepository
	rateLimits   cache.RateLimitRepository
	userRepo     repository.UserRepository
	registry     *pluginregistry.AuthnRegistry
	sessionTTL   time.Duration
	ratePolicy   RateLimitPolicy
	now          func() time.Time
}

func NewService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	sessionCache cache.SessionCacheRepository,
	rateLimits cache.RateLimitRepository,
	registry *pluginregistry.AuthnRegistry,
	sessionTTL time.Duration,
	ratePolicy RateLimitPolicy,
) *Service {
	if ratePolicy.FailureWindow <= 0 && ratePolicy.MaxFailuresPerIP == 0 && ratePolicy.MaxFailuresPerUser == 0 && ratePolicy.UserLockThreshold == 0 && ratePolicy.UserLockTTL == 0 {
		ratePolicy = DefaultRateLimitPolicy()
	}

	return &Service{
		sessionRepo:  sessionRepo,
		sessionCache: sessionCache,
		rateLimits:   rateLimits,
		userRepo:     userRepo,
		registry:     registry,
		sessionTTL:   sessionTTL,
		ratePolicy:   ratePolicy,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
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

	sessionID := uuid.NewString()
	expiresAt := now.Add(s.sessionTTL)
	acr, amrJSON := sessionAuthContext(methodType)
	model := &session.Model{
		SessionID:       sessionID,
		UserID:          user.ID,
		Subject:         user.UserUUID,
		ACR:             acr,
		AMRJSON:         amrJSON,
		IPAddress:       input.IPAddress,
		UserAgent:       input.UserAgent,
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
			IPAddress:       input.IPAddress,
			UserAgent:       input.UserAgent,
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
		RedirectURI:     authnResult.RedirectURI,
		AuthenticatedAt: now,
		ExpiresAt:       expiresAt,
	}, nil
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
