package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/operator_role_repository/*.sql
var operatorRoleRepositorySQLFS embed.FS

type operatorRoleRepositorySQLSet struct {
	upsert         string
	create         string
	update         string
	deleteByRole   string
	findByRoleCode string
	list           string
}

var operatorRoleRepositorySQL = mustLoadOperatorRoleRepositorySQL()

func mustLoadOperatorRoleRepositorySQL() operatorRoleRepositorySQLSet {
	return operatorRoleRepositorySQLSet{
		upsert:         mustReadOperatorRoleRepositorySQL("upsert.sql"),
		create:         mustReadOperatorRoleRepositorySQL("create.sql"),
		update:         mustReadOperatorRoleRepositorySQL("update.sql"),
		deleteByRole:   mustReadOperatorRoleRepositorySQL("delete_by_role_code.sql"),
		findByRoleCode: mustReadOperatorRoleRepositorySQL("find_by_role_code.sql"),
		list:           mustReadOperatorRoleRepositorySQL("list.sql"),
	}
}

func mustReadOperatorRoleRepositorySQL(fileName string) string {
	data, err := operatorRoleRepositorySQLFS.ReadFile(path.Join("sql/operator_role_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load operator role repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
