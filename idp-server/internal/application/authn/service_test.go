package authn

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	passkeydomain "idp-server/internal/domain/passkey"
	sessiondomain "idp-server/internal/domain/session"
	userdomain "idp-server/internal/domain/user"
	pluginregistry "idp-server/internal/plugins/registry"
	cacheport "idp-server/internal/ports/cache"
	pluginport "idp-server/internal/ports/plugin"
	securityport "idp-server/internal/ports/security"
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
	lockAccountCalls           int
	lockAccountID              int64
	lockAccountAt              time.Time
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

func (s *stubAuthnUserRepository) ListByRoleCode(context.Context, string, int) ([]*userdomain.Model, error) {
	return nil, nil
}

func (s *stubAuthnUserRepository) CountByRoleCode(context.Context, string) (int64, error) {
	return 0, nil
}

func (s *stubAuthnUserRepository) UpdateRoleAndPrivilege(context.Context, int64, string, uint32, string) error {
	return nil
}

func (s *stubAuthnUserRepository) UnlockAccount(context.Context, int64, time.Time) error {
	return nil
}

func (s *stubAuthnUserRepository) LockAccount(_ context.Context, id int64, updatedAt time.Time) error {
	s.lockAccountCalls++
	s.lockAccountID = id
	s.lockAccountAt = updatedAt
	if user := s.usersByUsername["alice"]; user != nil {
		user.Status = "locked"
	}
	return nil
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
	lockedIPs         map[string]bool
	blacklistFailures map[string]int64
	lastLockedUserID  string
	lastLockedUserTTL time.Duration
	resetUsernames    []string
	resetIPs          []string
}

func (s *stubAuthnRateLimitRepository) IncrementLoginFailByUser(
	_ context.Context,
	username, userID string,
	_ time.Duration,
	lockThreshold int64,
	_ time.Duration,
) (*cacheport.RateLimitIncrementResult, error) {
	if s.userFailures == nil {
		s.userFailures = map[string]int64{}
	}
	s.userFailures[username]++
	locked := false
	if lockThreshold > 0 && s.userFailures[username] >= lockThreshold && userID != "" {
		if s.lockedUsers == nil {
			s.lockedUsers = map[string]bool{}
		}
		s.lockedUsers[userID] = true
		locked = true
	}
	return &cacheport.RateLimitIncrementResult{
		Count:  s.userFailures[username],
		Locked: locked,
	}, nil
}

func (s *stubAuthnRateLimitRepository) IncrementLoginFailByIP(
	_ context.Context,
	ip string,
	_ time.Duration,
	lockThreshold int64,
	_ time.Duration,
) (*cacheport.RateLimitIncrementResult, error) {
	if s.ipFailures == nil {
		s.ipFailures = map[string]int64{}
	}
	s.ipFailures[ip]++
	locked := false
	if lockThreshold > 0 && s.ipFailures[ip] >= lockThreshold {
		if s.lockedIPs == nil {
			s.lockedIPs = map[string]bool{}
		}
		s.lockedIPs[ip] = true
		locked = true
	}
	return &cacheport.RateLimitIncrementResult{
		Count:  s.ipFailures[ip],
		Locked: locked,
	}, nil
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

func (s *stubAuthnRateLimitRepository) IncrementBlacklistByUser(_ context.Context, username, userID string, lockThreshold int64) (*cacheport.RateLimitIncrementResult, error) {
	if s.blacklistFailures == nil {
		s.blacklistFailures = map[string]int64{}
	}
	s.blacklistFailures[username]++
	locked := false
	if lockThreshold > 0 && s.blacklistFailures[username] >= lockThreshold && userID != "" {
		if s.lockedUsers == nil {
			s.lockedUsers = map[string]bool{}
		}
		s.lockedUsers[userID] = true
		locked = true
	}
	return &cacheport.RateLimitIncrementResult{
		Count:  s.blacklistFailures[username],
		Locked: locked,
	}, nil
}

func (s *stubAuthnRateLimitRepository) ResetBlacklistByUser(_ context.Context, username string) error {
	if s.blacklistFailures != nil {
		delete(s.blacklistFailures, username)
	}
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

func (s *stubAuthnRateLimitRepository) ClearUserLock(_ context.Context, userID string) error {
	if s.lockedUsers == nil {
		return nil
	}
	delete(s.lockedUsers, userID)
	return nil
}

func (s *stubAuthnRateLimitRepository) IsIPLocked(_ context.Context, ip string) (bool, error) {
	return s.lockedIPs[ip], nil
}

func (s *stubAuthnRateLimitRepository) ClearIPLock(_ context.Context, ip string) error {
	if s.lockedIPs == nil {
		return nil
	}
	delete(s.lockedIPs, ip)
	return nil
}

type stubAuthnMFARepository struct {
	challenges map[string]cacheport.MFAChallengeEntry
}

func (s *stubAuthnMFARepository) SaveTOTPEnrollment(context.Context, cacheport.TOTPEnrollmentEntry, time.Duration) error {
	return nil
}

func (s *stubAuthnMFARepository) GetTOTPEnrollment(context.Context, string) (*cacheport.TOTPEnrollmentEntry, error) {
	return nil, nil
}

func (s *stubAuthnMFARepository) DeleteTOTPEnrollment(context.Context, string) error {
	return nil
}

func (s *stubAuthnMFARepository) ReserveTOTPStepUse(context.Context, string, string, int64, time.Duration) (bool, error) {
	return true, nil
}

func (s *stubAuthnMFARepository) SaveMFAChallenge(_ context.Context, entry cacheport.MFAChallengeEntry, _ time.Duration) error {
	if s.challenges == nil {
		s.challenges = map[string]cacheport.MFAChallengeEntry{}
	}
	s.challenges[entry.ChallengeID] = entry
	return nil
}

func (s *stubAuthnMFARepository) GetMFAChallenge(_ context.Context, challengeID string) (*cacheport.MFAChallengeEntry, error) {
	entry, ok := s.challenges[challengeID]
	if !ok {
		return nil, nil
	}
	copy := entry
	return &copy, nil
}

func (s *stubAuthnMFARepository) DeleteMFAChallenge(_ context.Context, challengeID string) error {
	delete(s.challenges, challengeID)
	return nil
}

type stubAuthnPasskeyCredentialRepository struct {
	credentialsByUserID map[int64][]*passkeydomain.Model
	listByUserIDCalls   int
}

func (s *stubAuthnPasskeyCredentialRepository) ListByUserID(_ context.Context, userID int64) ([]*passkeydomain.Model, error) {
	s.listByUserIDCalls++
	return s.credentialsByUserID[userID], nil
}

func (s *stubAuthnPasskeyCredentialRepository) Upsert(context.Context, *passkeydomain.Model) error {
	return nil
}

func (s *stubAuthnPasskeyCredentialRepository) TouchByCredentialID(context.Context, string, time.Time) error {
	return nil
}

type stubAuthnPasskeyProvider struct{}

func (s *stubAuthnPasskeyProvider) BeginRegistration(securityport.PasskeyUser, []string) ([]byte, []byte, error) {
	return nil, nil, nil
}

func (s *stubAuthnPasskeyProvider) FinishRegistration(securityport.PasskeyUser, []string, []byte, []byte) (string, string, error) {
	return "", "", nil
}

func (s *stubAuthnPasskeyProvider) BeginLogin(securityport.PasskeyUser, []string) ([]byte, []byte, error) {
	return nil, nil, nil
}

func (s *stubAuthnPasskeyProvider) FinishLogin(securityport.PasskeyUser, []string, []byte, []byte) (string, string, error) {
	return "", "", nil
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
		&stubAuthnRateLimitRepository{lockedIPs: map[string]bool{"203.0.113.10": true}},
		nil,
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		nil,
		nil,
		8*time.Hour,
		5*time.Minute,
		false,
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
		nil,
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		nil,
		nil,
		8*time.Hour,
		5*time.Minute,
		false,
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
		usersByUsername: map[string]*userdomain.Model{"alice": user},
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
		nil,
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		nil,
		nil,
		8*time.Hour,
		5*time.Minute,
		false,
		RateLimitPolicy{
			FailureWindow:      15 * time.Minute,
			MaxFailuresPerIP:   20,
			MaxFailuresPerUser: 5,
			UserLockThreshold:  5,
			UserLockTTL:        30 * time.Minute,
		},
	)

	var err error
	for i := 0; i < 5; i++ {
		_, err = service.Authenticate(context.Background(), AuthenticateInput{
			Username:  "alice",
			Password:  "wrong",
			IPAddress: "203.0.113.10",
		})
	}
	if !errors.Is(err, ErrUserLocked) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrUserLocked)
	}
	if userRepo.findByUsernameCalls != 5 {
		t.Fatalf("FindByUsername calls = %d, want 5", userRepo.findByUsernameCalls)
	}
	if rateLimits.userFailures["alice"] != 5 {
		t.Fatalf("user failure count = %d, want 5", rateLimits.userFailures["alice"])
	}
	if rateLimits.ipFailures["203.0.113.10"] != 4 {
		t.Fatalf("ip failure count = %d, want 4", rateLimits.ipFailures["203.0.113.10"])
	}
	if !rateLimits.lockedUsers["42"] {
		t.Fatalf("locked user map = %#v, want user 42 to be locked", rateLimits.lockedUsers)
	}
}

func TestAuthenticatePasswordFailureLocksIPAtThreshold(t *testing.T) {
	user := &userdomain.Model{
		ID:           42,
		UserUUID:     "user-42",
		Username:     "alice",
		PasswordHash: "hashed:correct",
		Status:       "active",
	}
	userRepo := &stubAuthnUserRepository{
		usersByUsername: map[string]*userdomain.Model{"alice": user},
	}
	rateLimits := &stubAuthnRateLimitRepository{
		userFailures: map[string]int64{},
		ipFailures:   map[string]int64{},
		lockedUsers:  map[string]bool{},
		lockedIPs:    map[string]bool{},
	}
	service := NewService(
		userRepo,
		&stubAuthnSessionRepository{},
		&stubAuthnSessionCache{},
		rateLimits,
		nil,
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		nil,
		nil,
		8*time.Hour,
		5*time.Minute,
		false,
		RateLimitPolicy{
			FailureWindow:              15 * time.Minute,
			MaxFailuresPerIP:           1,
			MaxFailuresPerUser:         100,
			UserLockThreshold:          100,
			UserLockTTL:                30 * time.Minute,
			PermanentUserLockThreshold: 10,
		},
	)

	_, err := service.Authenticate(context.Background(), AuthenticateInput{
		Username:  "alice",
		Password:  "wrong",
		IPAddress: "203.0.113.10",
	})
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrRateLimited)
	}
	if !rateLimits.lockedIPs["203.0.113.10"] {
		t.Fatalf("locked ip map = %#v, want ip locked", rateLimits.lockedIPs)
	}
}

func TestAuthenticatePasswordFailureTriggersPermanentLockAfterBlacklistThreshold(t *testing.T) {
	user := &userdomain.Model{
		ID:           42,
		UserUUID:     "user-42",
		Username:     "alice",
		PasswordHash: "hashed:correct",
		Status:       "active",
	}
	userRepo := &stubAuthnUserRepository{
		usersByUsername: map[string]*userdomain.Model{"alice": user},
	}
	rateLimits := &stubAuthnRateLimitRepository{
		userFailures:      map[string]int64{},
		ipFailures:        map[string]int64{},
		blacklistFailures: map[string]int64{},
		lockedUsers:       map[string]bool{},
	}
	service := NewService(
		userRepo,
		&stubAuthnSessionRepository{},
		&stubAuthnSessionCache{},
		rateLimits,
		nil,
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		nil,
		nil,
		8*time.Hour,
		5*time.Minute,
		false,
		RateLimitPolicy{
			FailureWindow:              15 * time.Minute,
			MaxFailuresPerIP:           20,
			MaxFailuresPerUser:         100,
			UserLockThreshold:          100,
			UserLockTTL:                30 * time.Minute,
			PermanentUserLockThreshold: 2,
		},
	)

	for i := 0; i < 2; i++ {
		_, err := service.Authenticate(context.Background(), AuthenticateInput{
			Username:  "alice",
			Password:  "wrong",
			IPAddress: "203.0.113.10",
		})
		if i == 0 && !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("first attempt error = %v, want %v", err, ErrInvalidCredentials)
		}
		if i == 1 && !errors.Is(err, ErrUserLocked) {
			t.Fatalf("second attempt error = %v, want %v", err, ErrUserLocked)
		}
	}

	if !rateLimits.lockedUsers["42"] {
		t.Fatalf("locked user map = %#v, want user 42 to be locked", rateLimits.lockedUsers)
	}
	if userRepo.lockAccountCalls != 1 || userRepo.lockAccountID != 42 {
		t.Fatalf("lock account calls=%d id=%d, want 1 and 42", userRepo.lockAccountCalls, userRepo.lockAccountID)
	}
}

func TestAuthenticatePasswordRequiresEnrollmentWhenForcedAndNoTOTP(t *testing.T) {
	now := time.Date(2026, 4, 6, 9, 0, 0, 0, time.UTC)
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
		nil,
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		nil,
		nil,
		8*time.Hour,
		5*time.Minute,
		true,
		DefaultRateLimitPolicy(),
	)
	service.now = func() time.Time { return now }

	result, err := service.Authenticate(context.Background(), AuthenticateInput{
		Username:  "alice",
		Password:  "secret",
		IPAddress: "203.0.113.10",
		UserAgent: "test-agent",
		ReturnTo:  "/oauth2/authorize?client_id=demo",
	})
	if !errors.Is(err, ErrMFAEnrollmentRequired) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrMFAEnrollmentRequired)
	}
	if result == nil || result.SessionID == "" {
		t.Fatalf("result session = %#v, want non-empty session", result)
	}
	if !result.MFAEnrollmentRequired {
		t.Fatalf("MFAEnrollmentRequired = %v, want true", result.MFAEnrollmentRequired)
	}
	if sessionRepo.createCalls != 1 {
		t.Fatalf("session create calls = %d, want 1", sessionRepo.createCalls)
	}
}

func TestAuthenticatePasswordRequiresMFAWhenPasskeyExistsWithoutTOTP(t *testing.T) {
	now := time.Date(2026, 4, 9, 9, 17, 41, 0, time.UTC)
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
	mfaCache := &stubAuthnMFARepository{challenges: map[string]cacheport.MFAChallengeEntry{}}
	passkeyRepo := &stubAuthnPasskeyCredentialRepository{
		credentialsByUserID: map[int64][]*passkeydomain.Model{
			42: {
				{
					UserID:         42,
					CredentialID:   "cred-1",
					CredentialJSON: `{"id":"cred-1","type":"public-key"}`,
				},
			},
		},
	}
	service := NewService(
		userRepo,
		sessionRepo,
		sessionCache,
		rateLimits,
		mfaCache,
		pluginregistry.NewAuthnRegistry(&stubPasswordAuthnMethod{users: userRepo, passwords: &stubAuthnPasswordVerifier{}}),
		nil,
		nil,
		8*time.Hour,
		5*time.Minute,
		true,
		DefaultRateLimitPolicy(),
	).WithPasskey(passkeyRepo, &stubAuthnPasskeyProvider{})
	service.now = func() time.Time { return now }

	result, err := service.Authenticate(context.Background(), AuthenticateInput{
		Username:  "alice",
		Password:  "secret",
		IPAddress: "203.0.113.10",
		UserAgent: "test-agent",
		ReturnTo:  "/oauth2/authorize?client_id=demo",
	})
	if !errors.Is(err, ErrMFARequired) {
		t.Fatalf("Authenticate() error = %v, want %v", err, ErrMFARequired)
	}
	if result == nil {
		t.Fatalf("result = nil, want MFA challenge result")
	}
	if !result.MFARequired {
		t.Fatalf("MFARequired = %v, want true", result.MFARequired)
	}
	if result.MFAEnrollmentRequired {
		t.Fatalf("MFAEnrollmentRequired = %v, want false", result.MFAEnrollmentRequired)
	}
	if result.MFAChallengeID == "" {
		t.Fatalf("MFAChallengeID is empty, want non-empty challenge id")
	}
	if result.MFAMode != MFAModePasskeyTOTPFallback {
		t.Fatalf("MFAMode = %q, want %q", result.MFAMode, MFAModePasskeyTOTPFallback)
	}
	if !result.PasskeyAvailable {
		t.Fatalf("PasskeyAvailable = %v, want true", result.PasskeyAvailable)
	}
	if sessionRepo.createCalls != 0 {
		t.Fatalf("session create calls = %d, want 0", sessionRepo.createCalls)
	}
	if passkeyRepo.listByUserIDCalls != 1 {
		t.Fatalf("ListByUserID calls = %d, want 1", passkeyRepo.listByUserIDCalls)
	}
	if _, ok := mfaCache.challenges[result.MFAChallengeID]; !ok {
		t.Fatalf("challenge %q not stored in mfa cache", result.MFAChallengeID)
	}
	challenge := mfaCache.challenges[result.MFAChallengeID]
	if result.PushCode != challenge.PushCode {
		t.Fatalf("result push code = %q, challenge push code = %q, want equal", result.PushCode, challenge.PushCode)
	}
	if len(result.PushCode) != 2 {
		t.Fatalf("result push code length = %d, want 2", len(result.PushCode))
	}
	if _, err := strconv.Atoi(result.PushCode); err != nil {
		t.Fatalf("result push code = %q, want numeric", result.PushCode)
	}
}

func TestBuildPushMatchCodeReturnsTwoDigitCode(t *testing.T) {
	code, err := buildPushMatchCode()
	if err != nil {
		t.Fatalf("buildPushMatchCode() error = %v", err)
	}
	if len(code) != 2 {
		t.Fatalf("code length = %d, want 2", len(code))
	}
	value, err := strconv.Atoi(code)
	if err != nil {
		t.Fatalf("code = %q, want numeric", code)
	}
	if value < 10 || value > 99 {
		t.Fatalf("code value = %d, want [10,99]", value)
	}
}
