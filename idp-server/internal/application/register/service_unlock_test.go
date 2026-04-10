package register

import (
	"context"
	"testing"
	"time"

	userdomain "idp-server/internal/domain/user"
)

type stubRegisterUserRepository struct {
	user        *userdomain.Model
	unlockCalls int
	unlockID    int64
	unlockAt    time.Time
}

func (s *stubRegisterUserRepository) Create(context.Context, *userdomain.Model) error {
	return nil
}

func (s *stubRegisterUserRepository) FindByID(context.Context, int64) (*userdomain.Model, error) {
	return s.user, nil
}

func (s *stubRegisterUserRepository) FindByUserUUID(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}

func (s *stubRegisterUserRepository) FindByEmail(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}

func (s *stubRegisterUserRepository) FindByUsername(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}

func (s *stubRegisterUserRepository) ListByRoleCode(context.Context, string, int) ([]*userdomain.Model, error) {
	return nil, nil
}

func (s *stubRegisterUserRepository) CountByRoleCode(context.Context, string) (int64, error) {
	return 0, nil
}

func (s *stubRegisterUserRepository) UpdateRoleAndPrivilege(context.Context, int64, string, uint32, string) error {
	return nil
}

func (s *stubRegisterUserRepository) UnlockAccount(_ context.Context, id int64, updatedAt time.Time) error {
	s.unlockCalls++
	s.unlockID = id
	s.unlockAt = updatedAt
	return nil
}

func (s *stubRegisterUserRepository) IncrementFailedLogin(context.Context, int64) (int64, error) {
	return 0, nil
}

func (s *stubRegisterUserRepository) ResetFailedLogin(context.Context, int64, time.Time) error {
	return nil
}

type stubRegisterRateLimitRepository struct {
	clearedUserLocks []string
	resetUsers       []string
}

func (s *stubRegisterRateLimitRepository) IncrementLoginFailByUser(context.Context, string, time.Duration) (int64, error) {
	return 0, nil
}

func (s *stubRegisterRateLimitRepository) IncrementLoginFailByIP(context.Context, string, time.Duration) (int64, error) {
	return 0, nil
}

func (s *stubRegisterRateLimitRepository) GetLoginFailByUser(context.Context, string) (int64, error) {
	return 0, nil
}

func (s *stubRegisterRateLimitRepository) GetLoginFailByIP(context.Context, string) (int64, error) {
	return 0, nil
}

func (s *stubRegisterRateLimitRepository) ResetLoginFailByUser(_ context.Context, username string) error {
	s.resetUsers = append(s.resetUsers, username)
	return nil
}

func (s *stubRegisterRateLimitRepository) ResetLoginFailByIP(context.Context, string) error {
	return nil
}

func (s *stubRegisterRateLimitRepository) SetUserLock(context.Context, string, time.Duration) error {
	return nil
}

func (s *stubRegisterRateLimitRepository) IsUserLocked(context.Context, string) (bool, error) {
	return false, nil
}

func (s *stubRegisterRateLimitRepository) ClearUserLock(_ context.Context, userID string) error {
	s.clearedUserLocks = append(s.clearedUserLocks, userID)
	return nil
}

func TestAdminUnlockUserClearsDBAndRateLimitState(t *testing.T) {
	now := time.Date(2026, 4, 10, 3, 0, 0, 0, time.UTC)
	userRepo := &stubRegisterUserRepository{
		user: &userdomain.Model{
			ID:       42,
			Username: "bob",
			Status:   "locked",
		},
	}
	rateLimitRepo := &stubRegisterRateLimitRepository{}
	service := NewService(userRepo, nil, rateLimitRepo)
	service.now = func() time.Time { return now }

	result, err := service.AdminUnlockUser(context.Background(), AdminUnlockUserInput{
		UserID: 42,
	})
	if err != nil {
		t.Fatalf("AdminUnlockUser() error = %v", err)
	}
	if result.UserID != 42 || result.Username != "bob" {
		t.Fatalf("result = %#v, want user_id=42 username=bob", result)
	}
	if result.UnlockedAt != now {
		t.Fatalf("unlocked_at = %s, want %s", result.UnlockedAt, now)
	}
	if userRepo.unlockCalls != 1 || userRepo.unlockID != 42 || userRepo.unlockAt != now {
		t.Fatalf("unlock call state = calls:%d id:%d at:%s", userRepo.unlockCalls, userRepo.unlockID, userRepo.unlockAt)
	}
	if len(rateLimitRepo.clearedUserLocks) != 1 || rateLimitRepo.clearedUserLocks[0] != "42" {
		t.Fatalf("cleared user locks = %#v, want [\"42\"]", rateLimitRepo.clearedUserLocks)
	}
	if len(rateLimitRepo.resetUsers) != 1 || rateLimitRepo.resetUsers[0] != "bob" {
		t.Fatalf("reset users = %#v, want [\"bob\"]", rateLimitRepo.resetUsers)
	}
}
