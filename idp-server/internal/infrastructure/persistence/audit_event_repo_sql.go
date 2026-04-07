package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/audit_event_repository/*.sql
var auditEventRepositorySQLFS embed.FS

type auditEventRepositorySQLSet struct {
	create string
}

var auditEventRepositorySQL = mustLoadAuditEventRepositorySQL()

func mustLoadAuditEventRepositorySQL() auditEventRepositorySQLSet {
	return auditEventRepositorySQLSet{
		create: mustReadAuditEventRepositorySQL("create.sql"),
	}
}

func mustReadAuditEventRepositorySQL(fileName string) string {
	data, err := auditEventRepositorySQLFS.ReadFile(path.Join("sql/audit_event_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load audit event repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
