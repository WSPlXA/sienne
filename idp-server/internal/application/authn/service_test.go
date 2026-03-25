package authn

import (
	"context"
	"errors"
	"testing"
	"time"

	sessiondomain "idp-server/internal/domain/session"
	userdomain "idp-server/internal/domain/user"
	pluginregistry "idp-server/internal/plugins/registry"
	cacheport "idp-server/internal/ports/cache"
	pluginport "idp-server/internal/ports/plugin"
)

type stubAuthnUserRepository struct {
	usersByUsername            map[string]*userdomain.Model
	usersByUUID                map[string]*userdomain.Model
	usersByEmail               map[string]*userdomain.Model
	findByUsernameCalls        int
	findByUserUUIDCalls        int
	findByEmailCalls           int
	incrementFailedLoginCalls  int
	incrementFailedLoginResult int64
	resetFailedLoginCalls      int
	resetFailedLoginUserID     int64
	resetFailedLoginAt         time.Time
}

func (s *stubAuthnUserRepository) Create(context.Context, *userdomain.Model) error {
	return nil
}

func (s *stubAuthnUserRepository) FindByID(context.Context, int64) (*userdomain.Model, error) {
	return nil, nil
}

func (s *stubAuthnUserRepository) FindByUserUUID(_ context.Context, userUUID string) (*userdomain.Model, error) {
	s.findByUserUUIDCalls++
	return s.usersByUUID[userUUID], nil
}

func (s *stubAuthnUserRepository) FindByEmail(_ context.Context, email string) (*userdomain.Model, error) {
	s.findByEmailCalls++
	return s.usersByEmail[email], nil
}

func (s *stubAuthnUserRepository) FindByUsername(_ context.Context, username string) (*userdomain.Model, error) {
	s.findByUsernameCalls++
	return s.usersByUsername[username], nil
}

func (s *stubAuthnUserRepository) IncrementFailedLogin(context.Context, int64) (int64, error) {
	s.incrementFailedLoginCalls++
	return s.incrementFailedLoginResult, nil
}

func (s *stubAuthnUserRepository) ResetFailedLogin(_ context.Context, id int64, lastLoginAt time.Time) error {
	s.resetFailedLoginCalls++
	s.resetFailedLoginUserID = id
	s.resetFailedLoginAt = lastLoginAt
	return nil
}

type stubAuthnSessionRepository struct {
	createCalls int
	lastCreated *sessiondomain.Model
}

func (s *stubAuthnSessionRepository) Create(_ context.Context, model *sessiondomain.Model) error {
	s.createCalls++
	copy := *model
	s.lastCreated = &copy
	return nil
}

func (s *stubAuthnSessionRepository) FindBySessionID(context.Context, string) (*sessiondomain.Model, error) {
	return nil, nil
}

func (s *stubAuthnSessionRepository) ListActiveByUserID(context.Context, int64) ([]*sessiondomain.Model, error) {
	return nil, nil
}

func (s *stubAuthnSessionRepository) LogoutBySessionID(context.Context, string, time.Time) error {
	return nil
}

func (s *stubAuthnSessionRepository) LogoutAllByUserID(context.Context, int64, time.Time) error {
	return nil
}

type stubAuthnSessionCache struct {
	saveCalls int
	lastEntry cacheport.SessionCacheEntry
	lastTTL   time.Duration
}

func (s *stubAuthnSessionCache) Save(_ context.Context, entry cacheport.SessionCacheEntry, ttl time.Duration) error {
	s.saveCalls++
	s.lastEntry = entry
	s.lastTTL = ttl
	return nil
}

func (s *stubAuthnSessionCache) Get(context.Context, string) (*cacheport.SessionCacheEntry, error) {
	return nil, nil
}

func (s *stubAuthnSessionCache) Delete(context.Context, string) error {
	return nil
}

func (s *stubAuthnSessionCache) AddUserSessionIndex(context.Context, string, string, time.Duration) error {
	return nil
}

func (s *stubAuthnSessionCache) ListUserSessionIDs(context.Context, string) ([]string, error) {
	return nil, nil
}

func (s *stubAuthnSessionCache) RemoveUserSessionIndex(context.Context, string, string) error {
	return nil
}

type stubAuthnRateLimitRepository struct {
	userFailures      map[string]int64
	ipFailures        map[string]int64
	lockedUsers       map[string]bool
	lastLockedUserID  string
	lastLockedUserTTL time.Duration
	resetUsernames    []string
	resetIPs          []string
}

func (s *stubAuthnRateLimitRepository) IncrementLoginFailByUser(_ context.Context, username string, _ time.Duration) (int64, error) {
	if s.userFailures == nil {
		s.userFailures = map[string]int64{}
	}
	s.userFailures[username]++
	return s.userFailures[username], nil
}

func (s *stubAuthnRateLimitRepository) IncrementLoginFailByIP(_ context.Context, ip string, _ time.Duration) (int64, error) {
	if s.ipFailures == nil {
		s.ipFailures = map[string]int64{}
	}
	s.ipFailures[ip]++
	return s.ipFailures[ip], nil
}

func (s *stubAuthnRateLimitRepository) GetLoginFailByUser(context.Context, string) (int64, error) {
	return s.userFailures["alice"], nil
}

func (s *stubAuthnRateLimitRepository) GetLoginFailByIP(context.Context, string) (int64, error) {
	return s.ipFailures["203.0.113.10"], nil
}

func (s *stubAuthnRateLimitRepository) ResetLoginFailByUser(_ context.Context, username string) error {
	s.resetUsernames = append(s.resetUsernames, username)
	return nil
}

func (s *stubAuthnRateLimitRepository) ResetLoginFailByIP(_ context.Context, ip string) error {
	s.resetIPs = append(s.resetIPs, ip)
	return nil
}

func (s *stubAuthnRateLimitRepository) SetUserLock(_ context.Context, userID string, ttl time.Duration) error {
	if s.lockedUsers == nil {
		s.lockedUsers = map[string]bool{}
	}
	s.lockedUsers[userID] = true
	s.lastLockedUserID = userID
	s.lastLockedUserTTL = ttl
	return nil
}

func (s *stubAuthnRateLimitRepository) IsUserLocked(_ context.Context, userID string) (bool, error) {
	return s.lockedUsers[userID], nil
}

type stubAuthnPasswordVerifier struct{}

func (s *stubAuthnPasswordVerifier) HashPassword(string) (string, error) {
	return "", nil
}

func (s *stubAuthnPasswordVerifier) VerifyPassword(password, encodedHash string) error {
	if encodedHash == "hashed:"+password {
		return nil
	}
	return errors.New("password mismatch")
}

type stubPasswordAuthnMethod struct {
	users     *stubAuthnUserRepository
	passwords *stubAuthnPasswordVerifier
}

func (s *stubPasswordAuthnMethod) Name() string {
	return "password"
}

func (s *stubPasswordAuthnMethod) Type() pluginport.AuthnMethodType {
	return pluginport.AuthnMethodTypePassword
}

func (s *stubPasswordAuthnMethod) Authenticate(ctx context.Context, input pluginport.AuthenticateInput) (*pluginport.AuthenticateResult, error) {
	user := input.User
	if user == nil {
		var err error
		user, err = s.users.FindByUsername(ctx, input.Username)
		if err != nil {
			return nil, err
		}
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}
	if err := s.passwords.VerifyPassword(input.Password, user.PasswordHash); err != nil {
		return nil, ErrInvalidCredentials
	}
	return &pluginport.AuthenticateResult{
		Handled:       true,
		Authenticated: true,
		UserID:        user.ID,
		UserStatus:    user.Status,
		Subject:       user.UserUUID,
		Username:      user.Username,
		DisplayName:   user.DisplayName,
		Email:         user.Email,
	}, nil
}

func TestAuthenticatePasswordRejectsRateLimitedIPBeforeLookup(t *testing.T) {
	userRepo := &stubAuthnUserRepository{}
	service := NewService(
		userRepo,
		&stubAuthnSessionRepository{},
		&stubAuthnSessionCache{},
		&stubAuthnRateLimitRepository{ipFailures: map[string]int64{"203.0.113.10": 20}},
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		8*time.Hour,
		RateLimitPolicy{FailureWindow: 15 * time.Minute, MaxFailuresPerIP: 20},
	)

	_, err := service.Authenticate(context.Background(), AuthenticateInput{
		Username:  "alice",
		Password:  "secret",
		IPAddress: "203.0.113.10",
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrRateLimited)
	}
	if userRepo.findByUsernameCalls != 0 {
		t.Fatalf("FindByUsername calls = %d, want 0", userRepo.findByUsernameCalls)
	}
}

func TestAuthenticatePasswordSuccessfulPathUsesSingleUserLookup(t *testing.T) {
	now := time.Date(2026, 3, 25, 10, 0, 0, 0, time.UTC)
	user := &userdomain.Model{
		ID:           42,
		UserUUID:     "user-42",
		Username:     "alice",
		Email:        "alice@example.com",
		DisplayName:  "Alice",
		PasswordHash: "hashed:secret",
		Status:       "active",
	}
	userRepo := &stubAuthnUserRepository{
		usersByUsername: map[string]*userdomain.Model{"alice": user},
		usersByUUID:     map[string]*userdomain.Model{"user-42": user},
		usersByEmail:    map[string]*userdomain.Model{"alice@example.com": user},
	}
	sessionRepo := &stubAuthnSessionRepository{}
	sessionCache := &stubAuthnSessionCache{}
	rateLimits := &stubAuthnRateLimitRepository{
		userFailures: map[string]int64{},
		ipFailures:   map[string]int64{},
		lockedUsers:  map[string]bool{},
	}
	service := NewService(
		userRepo,
		sessionRepo,
		sessionCache,
		rateLimits,
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		8*time.Hour,
		DefaultRateLimitPolicy(),
	)
	service.now = func() time.Time { return now }

	result, err := service.Authenticate(context.Background(), AuthenticateInput{
		Username:  "alice",
		Password:  "secret",
		IPAddress: "203.0.113.10",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if result.UserID != 42 {
		t.Fatalf("result user id = %d, want 42", result.UserID)
	}
	if userRepo.findByUsernameCalls != 1 {
		t.Fatalf("FindByUsername calls = %d, want 1", userRepo.findByUsernameCalls)
	}
	if userRepo.findByUserUUIDCalls != 0 {
		t.Fatalf("FindByUserUUID calls = %d, want 0", userRepo.findByUserUUIDCalls)
	}
	if userRepo.resetFailedLoginCalls != 1 || userRepo.resetFailedLoginUserID != 42 {
		t.Fatalf("ResetFailedLogin calls = %d userID = %d, want 1 and 42", userRepo.resetFailedLoginCalls, userRepo.resetFailedLoginUserID)
	}
	if len(rateLimits.resetUsernames) != 1 || rateLimits.resetUsernames[0] != "alice" {
		t.Fatalf("ResetLoginFailByUser = %#v, want [\"alice\"]", rateLimits.resetUsernames)
	}
	if sessionRepo.createCalls != 1 || sessionRepo.lastCreated == nil {
		t.Fatalf("session create calls = %d, want 1", sessionRepo.createCalls)
	}
	if sessionCache.saveCalls != 1 || sessionCache.lastEntry.UserID != "42" {
		t.Fatalf("session cache save calls = %d, userID = %q", sessionCache.saveCalls, sessionCache.lastEntry.UserID)
	}
}

func TestAuthenticatePasswordFailureLocksUserAtThreshold(t *testing.T) {
	user := &userdomain.Model{
		ID:           42,
		UserUUID:     "user-42",
		Username:     "alice",
		PasswordHash: "hashed:correct",
		Status:       "active",
	}
	userRepo := &stubAuthnUserRepository{
		usersByUsername:            map[string]*userdomain.Model{"alice": user},
		incrementFailedLoginResult: 5,
	}
	rateLimits := &stubAuthnRateLimitRepository{
		userFailures: map[string]int64{},
		ipFailures:   map[string]int64{},
		lockedUsers:  map[string]bool{},
	}
	service := NewService(
		userRepo,
		&stubAuthnSessionRepository{},
		&stubAuthnSessionCache{},
		rateLimits,
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		8*time.Hour,
		RateLimitPolicy{
			FailureWindow:      15 * time.Minute,
			MaxFailuresPerIP:   20,
			MaxFailuresPerUser: 5,
			UserLockThreshold:  5,
			UserLockTTL:        30 * time.Minute,
		},
	)

	_, err := service.Authenticate(context.Background(), AuthenticateInput{
		Username:  "alice",
		Password:  "wrong",
		IPAddress: "203.0.113.10",
	})
	if !errors.Is(err, ErrUserLocked) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrUserLocked)
	}
	if userRepo.findByUsernameCalls != 1 {
		t.Fatalf("FindByUsername calls = %d, want 1", userRepo.findByUsernameCalls)
	}
	if userRepo.incrementFailedLoginCalls != 1 {
		t.Fatalf("IncrementFailedLogin calls = %d, want 1", userRepo.incrementFailedLoginCalls)
	}
	if rateLimits.userFailures["alice"] != 1 {
		t.Fatalf("user failure count = %d, want 1", rateLimits.userFailures["alice"])
	}
	if rateLimits.ipFailures["203.0.113.10"] != 1 {
		t.Fatalf("ip failure count = %d, want 1", rateLimits.ipFailures["203.0.113.10"])
	}
	if rateLimits.lastLockedUserID != "42" {
		t.Fatalf("locked user id = %q, want 42", rateLimits.lastLockedUserID)
	}
	if rateLimits.lastLockedUserTTL != 30*time.Minute {
		t.Fatalf("locked ttl = %s, want 30m", rateLimits.lastLockedUserTTL)
	}
}
