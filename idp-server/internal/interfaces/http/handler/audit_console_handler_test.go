package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auditdomain "idp-server/internal/domain/audit"
	sessiondomain "idp-server/internal/domain/session"
	userdomain "idp-server/internal/domain/user"
	httpmiddleware "idp-server/internal/interfaces/http/middleware"
	"idp-server/internal/ports/repository"

	"github.com/gin-gonic/gin"
)

type stubAuditConsoleUserRepository struct {
	usersByID       map[int64]*userdomain.Model
	usersByUsername map[string]*userdomain.Model
}

func (s *stubAuditConsoleUserRepository) Create(context.Context, *userdomain.Model) error { return nil }
func (s *stubAuditConsoleUserRepository) FindByID(_ context.Context, id int64) (*userdomain.Model, error) {
	if model, ok := s.usersByID[id]; ok {
		return model, nil
	}
	return nil, nil
}
func (s *stubAuditConsoleUserRepository) FindByUserUUID(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubAuditConsoleUserRepository) FindByEmail(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubAuditConsoleUserRepository) FindByUsername(_ context.Context, username string) (*userdomain.Model, error) {
	if model, ok := s.usersByUsername[username]; ok {
		return model, nil
	}
	return nil, nil
}
func (s *stubAuditConsoleUserRepository) ListByRoleCode(context.Context, string, int) ([]*userdomain.Model, error) {
	return nil, nil
}
func (s *stubAuditConsoleUserRepository) CountByRoleCode(context.Context, string) (int64, error) {
	return 0, nil
}
func (s *stubAuditConsoleUserRepository) UpdateRoleAndPrivilege(context.Context, int64, string, uint32, string) error {
	return nil
}
func (s *stubAuditConsoleUserRepository) UnlockAccount(context.Context, int64, time.Time) error {
	return nil
}
func (s *stubAuditConsoleUserRepository) IncrementFailedLogin(context.Context, int64) (int64, error) {
	return 0, nil
}
func (s *stubAuditConsoleUserRepository) ResetFailedLogin(context.Context, int64, time.Time) error {
	return nil
}

func TestAuditConsoleHandlerRendersAuditRows(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	auditRepo := &stubAuditEventRepository{
		events: []*auditdomain.Model{
			{
				ID:           1001,
				EventType:    "auth.login.succeeded",
				UserID:       ptrInt64(2),
				Subject:      "user-2",
				IPAddress:    "10.0.0.1",
				UserAgent:    "Mozilla/5.0",
				MetadataJSON: `{"method":"password"}`,
				CreatedAt:    now,
			},
			{
				ID:           1002,
				EventType:    "rbac.role.assigned",
				UserID:       ptrInt64(7),
				Subject:      "user:42",
				IPAddress:    "10.0.0.2",
				UserAgent:    "curl/8.0",
				MetadataJSON: `{"role_code":"support"}`,
				CreatedAt:    now.Add(-time.Minute),
			},
		},
	}
	userRepo := &stubAuditConsoleUserRepository{
		usersByID: map[int64]*userdomain.Model{
			2: {ID: 2, Username: "bob"},
			7: {ID: 7, Username: "alice-admin"},
		},
		usersByUsername: map[string]*userdomain.Model{
			"bob": {ID: 2, Username: "bob"},
		},
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(httpmiddleware.ContextAdminUser, &userdomain.Model{
			ID:            7,
			Username:      "alice-admin",
			RoleCode:      "support",
			PrivilegeMask: 0xCC8C888C,
		})
		c.Set(httpmiddleware.ContextAdminSession, &sessiondomain.Model{ID: 11, SessionID: "session-11"})
		c.Next()
	})
	router.GET("/admin/audit", NewAuditConsoleHandler(auditRepo, userRepo).Handle)

	req := httptest.NewRequest(http.MethodGet, "/admin/audit?limit=50", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Audit Console") {
		t.Fatalf("body should contain audit console title, got: %s", body)
	}
	if !strings.Contains(body, "auth.login.succeeded") {
		t.Fatalf("body should contain login event row, got: %s", body)
	}
	if !strings.Contains(body, "rbac.role.assigned") {
		t.Fatalf("body should contain operation event row, got: %s", body)
	}
	if !strings.Contains(body, "bob (id=2)") {
		t.Fatalf("body should resolve actor username, got: %s", body)
	}
}

func TestAuditConsoleHandlerFiltersByActorUsername(t *testing.T) {
	gin.SetMode(gin.TestMode)

	auditRepo := &stubAuditEventRepository{
		events: []*auditdomain.Model{
			{ID: 1, EventType: "auth.login.succeeded", UserID: ptrInt64(2), CreatedAt: time.Now().UTC()},
			{ID: 2, EventType: "rbac.role.assigned", UserID: ptrInt64(7), CreatedAt: time.Now().UTC().Add(-time.Minute)},
		},
	}
	userRepo := &stubAuditConsoleUserRepository{
		usersByID: map[int64]*userdomain.Model{
			2: {ID: 2, Username: "bob"},
			7: {ID: 7, Username: "alice-admin"},
		},
		usersByUsername: map[string]*userdomain.Model{
			"bob": {ID: 2, Username: "bob"},
		},
	}

	router := gin.New()
	router.GET("/admin/audit", NewAuditConsoleHandler(auditRepo, userRepo).Handle)

	req := httptest.NewRequest(http.MethodGet, "/admin/audit?actor_username=bob", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if strings.Contains(body, `"ID":2`) {
		t.Fatalf("response should exclude non-bob events, got: %s", body)
	}
	if !strings.Contains(body, `"ID":1`) {
		t.Fatalf("response should include bob event, got: %s", body)
	}
}

var _ repository.UserRepository = (*stubAuditConsoleUserRepository)(nil)
