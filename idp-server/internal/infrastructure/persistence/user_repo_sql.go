package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/user_repository/*.sql
var userRepositorySQLFS embed.FS

type userRepositorySQLSet struct {
	createUser                     string
	findByID                       string
	findByUsername                 string
	findByEmail                    string
	findByUserUUID                 string
	listByRoleCode                 string
	countByRoleCode                string
	updateRoleAndPrivilege         string
	incrementFailedLogin           string
	selectFailedLoginCountByUserID string
	resetFailedLogin               string
}

var userRepositorySQL = mustLoadUserRepositorySQL()

func mustLoadUserRepositorySQL() userRepositorySQLSet {
	return userRepositorySQLSet{
		createUser:                     mustReadUserRepositorySQL("create_user.sql"),
		findByID:                       mustReadUserRepositorySQL("find_by_id.sql"),
		findByUsername:                 mustReadUserRepositorySQL("find_by_username.sql"),
		findByEmail:                    mustReadUserRepositorySQL("find_by_email.sql"),
		findByUserUUID:                 mustReadUserRepositorySQL("find_by_user_uuid.sql"),
		listByRoleCode:                 mustReadUserRepositorySQL("list_by_role_code.sql"),
		countByRoleCode:                mustReadUserRepositorySQL("count_by_role_code.sql"),
		updateRoleAndPrivilege:         mustReadUserRepositorySQL("update_role_and_privilege.sql"),
		incrementFailedLogin:           mustReadUserRepositorySQL("increment_failed_login.sql"),
		selectFailedLoginCountByUserID: mustReadUserRepositorySQL("select_failed_login_count_by_user_id.sql"),
		resetFailedLogin:               mustReadUserRepositorySQL("reset_failed_login.sql"),
	}
}

func mustReadUserRepositorySQL(fileName string) string {
	data, err := userRepositorySQLFS.ReadFile(path.Join("sql/user_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load user repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
