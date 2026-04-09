package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sessiondomain "idp-server/internal/domain/session"
	userdomain "idp-server/internal/domain/user"
	cacheport "idp-server/internal/ports/cache"
	"idp-server/pkg/rbac"

	"github.com/gin-gonic/gin"
)

type stubAdminSessionRepository struct {
	session *sessiondomain.Model
}

func (s *stubAdminSessionRepository) Create(context.Context, *sessiondomain.Model) error {
	return nil
}

func (s *stubAdminSessionRepository) FindBySessionID(context.Context, string) (*sessiondomain.Model, error) {
	return s.session, nil
}

func (s *stubAdminSessionRepository) ListActiveByUserID(context.Context, int64) ([]*sessiondomain.Model, error) {
	return nil, nil
}

func (s *stubAdminSessionRepository) LogoutBySessionID(context.Context, string, time.Time) error {
	return nil
}

func (s *stubAdminSessionRepository) LogoutAllByUserID(context.Context, int64, time.Time) error {
	return nil
}

type stubAdminSessionCache struct{}

func (s *stubAdminSessionCache) Save(context.Context, cacheport.SessionCacheEntry, time.Duration) error {
	return nil
}
func (s *stubAdminSessionCache) Get(context.Context, string) (*cacheport.SessionCacheEntry, error) {
	return nil, nil
}
func (s *stubAdminSessionCache) Delete(context.Context, string) error { return nil }
func (s *stubAdminSessionCache) AddUserSessionIndex(context.Context, string, string, time.Duration) error {
	return nil
}
func (s *stubAdminSessionCache) ListUserSessionIDs(context.Context, string) ([]string, error) {
	return nil, nil
}
func (s *stubAdminSessionCache) RemoveUserSessionIndex(context.Context, string, string) error {
	return nil
}

type stubAdminUserRepository struct {
	user *userdomain.Model
}

func (s *stubAdminUserRepository) Create(context.Context, *userdomain.Model) error { return nil }
func (s *stubAdminUserRepository) FindByID(context.Context, int64) (*userdomain.Model, error) {
	return s.user, nil
}
func (s *stubAdminUserRepository) FindByUserUUID(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubAdminUserRepository) FindByEmail(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubAdminUserRepository) FindByUsername(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubAdminUserRepository) ListByRoleCode(context.Context, string, int) ([]*userdomain.Model, error) {
	return nil, nil
}
func (s *stubAdminUserRepository) CountByRoleCode(context.Context, string) (int64, error) {
	return 0, nil
}
func (s *stubAdminUserRepository) UpdateRoleAndPrivilege(context.Context, int64, string, uint32, string) error {
	return nil
}
func (s *stubAdminUserRepository) IncrementFailedLogin(context.Context, int64) (int64, error) {
	return 0, nil
}
func (s *stubAdminUserRepository) ResetFailedLogin(context.Context, int64, time.Time) error {
	return nil
}

func TestRequireSessionPermissionsAllowsPrivilegedUser(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	mw := NewSessionPermissionMiddleware(
		&stubAdminSessionRepository{session: &sessiondomain.Model{
			SessionID: "session-1",
			UserID:    7,
			ACR:       "urn:idp:acr:mfa",
			AMRJSON:   `["pwd","otp"]`,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}},
		&stubAdminSessionCache{},
		&stubAdminUserRepository{user: &userdomain.Model{
			ID:            7,
			Status:        "active",
			PrivilegeMask: rbac.MaskSuperAdmin,
		}},
	)

	router.POST("/admin", mw.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-1"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestRequireSessionPermissionsRejectsInsufficientPrivilege(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	mw := NewSessionPermissionMiddleware(
		&stubAdminSessionRepository{session: &sessiondomain.Model{
			SessionID: "session-1",
			UserID:    7,
			ACR:       "urn:idp:acr:mfa",
			AMRJSON:   `["pwd","otp"]`,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}},
		&stubAdminSessionCache{},
		&stubAdminUserRepository{user: &userdomain.Model{
			ID:            7,
			Status:        "active",
			PrivilegeMask: rbac.MaskSupport,
		}},
	)

	router.POST("/admin", mw.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodPost, "/admin", nil)
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-1"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusForbidden)
	}
}

func TestRequireSessionPermissionsShowsAlertForInsufficientPrivilegeHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	mw := NewSessionPermissionMiddleware(
		&stubAdminSessionRepository{session: &sessiondomain.Model{
			SessionID: "session-1",
			UserID:    7,
			ACR:       "urn:idp:acr:mfa",
			AMRJSON:   `["pwd","otp"]`,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}},
		&stubAdminSessionCache{},
		&stubAdminUserRepository{user: &userdomain.Model{
			ID:            7,
			Status:        "active",
			PrivilegeMask: rbac.MaskSupport,
		}},
	)

	router.GET("/admin/secure", mw.RequireSessionPermissions(rbac.AuthExec, rbac.UserManage), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/secure", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-1"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("content-type = %q, want text/html", contentType)
	}
	if body := recorder.Body.String(); !strings.Contains(body, "window.alert") || !strings.Contains(body, "insufficient privilege") {
		t.Fatalf("response body should contain popup script, got: %q", body)
	}
}

func TestRequireSessionPermissionsRedirectsHTMLWhenSessionMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	mw := NewSessionPermissionMiddleware(
		&stubAdminSessionRepository{},
		&stubAdminSessionCache{},
		&stubAdminUserRepository{},
	)

	router.GET("/admin", mw.RequireSessionPermissions(rbac.AuthExec), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Accept", "text/html")
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/login?return_to=%2Fadmin" {
		t.Fatalf("location = %q, want /login?return_to=%%2Fadmin", got)
	}
}

func TestRequireSessionPermissionsRejectsSessionWithoutOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	mw := NewSessionPermissionMiddleware(
		&stubAdminSessionRepository{session: &sessiondomain.Model{
			SessionID: "session-1",
			UserID:    7,
			ACR:       "urn:idp:acr:pwd",
			AMRJSON:   `["pwd"]`,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}},
		&stubAdminSessionCache{},
		&stubAdminUserRepository{user: &userdomain.Model{
			ID:            7,
			Status:        "active",
			PrivilegeMask: rbac.MaskSuperAdmin,
		}},
	)

	router.GET("/admin", mw.RequireSessionPermissions(rbac.OpsRead), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-1"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
}

func TestRequireSessionPermissionsRedirectsToTotpSetupWhenSessionWithoutOTPAndHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	mw := NewSessionPermissionMiddleware(
		&stubAdminSessionRepository{session: &sessiondomain.Model{
			SessionID: "session-1",
			UserID:    7,
			ACR:       "urn:idp:acr:pwd",
			AMRJSON:   `["pwd"]`,
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}},
		&stubAdminSessionCache{},
		&stubAdminUserRepository{user: &userdomain.Model{
			ID:            7,
			Status:        "active",
			PrivilegeMask: rbac.MaskSuperAdmin,
		}},
	)

	router.GET("/admin", mw.RequireSessionPermissions(rbac.OpsRead), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "idp_session", Value: "session-1"})
	recorder := httptest.NewRecorder()

	router.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusFound {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusFound)
	}
	if got := recorder.Header().Get("Location"); got != "/mfa/totp/setup?return_to=%2Fadmin" {
		t.Fatalf("location = %q, want /mfa/totp/setup?return_to=%%2Fadmin", got)
	}
}
