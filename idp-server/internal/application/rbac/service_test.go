package rbac

import (
	"context"
	"testing"
	"time"

	operatorroledomain "idp-server/internal/domain/operatorrole"
	userdomain "idp-server/internal/domain/user"
)

type stubRoleRepository struct {
	roles    map[string]*operatorroledomain.Model
	upserts  []operatorroledomain.Model
	listResp []*operatorroledomain.Model
}

func (s *stubRoleRepository) Upsert(_ context.Context, model *operatorroledomain.Model) error {
	copyModel := *model
	s.upserts = append(s.upserts, copyModel)
	if s.roles == nil {
		s.roles = map[string]*operatorroledomain.Model{}
	}
	s.roles[model.RoleCode] = &copyModel
	return nil
}

func (s *stubRoleRepository) Create(_ context.Context, model *operatorroledomain.Model) error {
	return s.Upsert(context.Background(), model)
}

func (s *stubRoleRepository) Update(_ context.Context, model *operatorroledomain.Model) error {
	if s.roles == nil {
		s.roles = map[string]*operatorroledomain.Model{}
	}
	copyModel := *model
	s.roles[model.RoleCode] = &copyModel
	return nil
}

func (s *stubRoleRepository) DeleteByRoleCode(_ context.Context, roleCode string) error {
	delete(s.roles, roleCode)
	return nil
}

func (s *stubRoleRepository) FindByRoleCode(_ context.Context, roleCode string) (*operatorroledomain.Model, error) {
	return s.roles[roleCode], nil
}

func (s *stubRoleRepository) List(context.Context) ([]*operatorroledomain.Model, error) {
	return s.listResp, nil
}

type stubRBACUserRepository struct {
	user        *userdomain.Model
	users       []*userdomain.Model
	roleCount   int64
	updatedID   int64
	updatedRole string
	updatedMask uint32
}

func (s *stubRBACUserRepository) Create(context.Context, *userdomain.Model) error { return nil }
func (s *stubRBACUserRepository) FindByID(context.Context, int64) (*userdomain.Model, error) {
	return s.user, nil
}
func (s *stubRBACUserRepository) FindByUserUUID(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubRBACUserRepository) FindByEmail(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubRBACUserRepository) FindByUsername(context.Context, string) (*userdomain.Model, error) {
	return nil, nil
}
func (s *stubRBACUserRepository) ListByRoleCode(context.Context, string, int) ([]*userdomain.Model, error) {
	return s.users, nil
}
func (s *stubRBACUserRepository) CountByRoleCode(context.Context, string) (int64, error) {
	return s.roleCount, nil
}
func (s *stubRBACUserRepository) UpdateRoleAndPrivilege(_ context.Context, id int64, roleCode string, privilegeMask uint32, _ string) error {
	s.updatedID = id
	s.updatedRole = roleCode
	s.updatedMask = privilegeMask
	return nil
}
func (s *stubRBACUserRepository) IncrementFailedLogin(context.Context, int64) (int64, error) {
	return 0, nil
}
func (s *stubRBACUserRepository) ResetFailedLogin(context.Context, int64, time.Time) error {
	return nil
}

func TestBootstrapBuiltinRoles(t *testing.T) {
	repo := &stubRoleRepository{}
	service := NewService(repo, &stubRBACUserRepository{})

	result, err := service.BootstrapBuiltinRoles(context.Background())
	if err != nil {
		t.Fatalf("BootstrapBuiltinRoles() error = %v", err)
	}
	if len(result.Roles) == 0 || len(repo.upserts) == 0 {
		t.Fatal("expected builtin roles to be upserted")
	}
}

func TestAssignRole(t *testing.T) {
	roleRepo := &stubRoleRepository{
		roles: map[string]*operatorroledomain.Model{
			"support": {RoleCode: "support", PrivilegeMask: 3431757964},
		},
	}
	userRepo := &stubRBACUserRepository{
		user: &userdomain.Model{ID: 42, Username: "alice"},
	}
	service := NewService(roleRepo, userRepo)

	result, err := service.AssignRole(context.Background(), AssignRoleInput{
		UserID:   42,
		RoleCode: "support",
	})
	if err != nil {
		t.Fatalf("AssignRole() error = %v", err)
	}
	if userRepo.updatedID != 42 || userRepo.updatedRole != "support" {
		t.Fatalf("updated user = %d/%q", userRepo.updatedID, userRepo.updatedRole)
	}
	if result.RoleCode != "support" {
		t.Fatalf("result role code = %q", result.RoleCode)
	}
}

func TestCreateRole(t *testing.T) {
	roleRepo := &stubRoleRepository{roles: map[string]*operatorroledomain.Model{}}
	service := NewService(roleRepo, &stubRBACUserRepository{})

	result, err := service.CreateRole(context.Background(), UpsertRoleInput{
		RoleCode:      "custom_ops",
		DisplayName:   "Custom Ops",
		Description:   "custom operations role",
		PrivilegeMask: 0x0000000E,
	})
	if err != nil {
		t.Fatalf("CreateRole() error = %v", err)
	}
	if result.Role.RoleCode != "custom_ops" {
		t.Fatalf("created role = %q", result.Role.RoleCode)
	}
}

func TestDeleteRoleRejectsSystemRole(t *testing.T) {
	roleRepo := &stubRoleRepository{
		roles: map[string]*operatorroledomain.Model{
			"super_admin": {RoleCode: "super_admin", IsSystem: true},
		},
	}
	service := NewService(roleRepo, &stubRBACUserRepository{})

	err := service.DeleteRole(context.Background(), DeleteRoleInput{RoleCode: "super_admin"})
	if err != ErrSystemRoleImmutable {
		t.Fatalf("DeleteRole() error = %v, want %v", err, ErrSystemRoleImmutable)
	}
}

func TestRoleUsage(t *testing.T) {
	roleRepo := &stubRoleRepository{
		listResp: []*operatorroledomain.Model{
			{RoleCode: "support", DisplayName: "Support", PrivilegeMask: 1},
		},
	}
	userRepo := &stubRBACUserRepository{roleCount: 3}
	service := NewService(roleRepo, userRepo)

	result, err := service.RoleUsage(context.Background())
	if err != nil {
		t.Fatalf("RoleUsage() error = %v", err)
	}
	if len(result.Roles) != 1 || result.Roles[0].UserCount != 3 {
		t.Fatalf("role usage = %#v", result.Roles)
	}
}
