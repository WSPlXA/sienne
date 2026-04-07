package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/totp_repository/*.sql
var totpRepositorySQLFS embed.FS

type totpRepositorySQLSet struct {
	findByUserID string
	upsert       string
	deleteByUser string
}

var totpRepositorySQL = mustLoadTOTPRepositorySQL()

func mustLoadTOTPRepositorySQL() totpRepositorySQLSet {
	return totpRepositorySQLSet{
		findByUserID: mustReadTOTPRepositorySQL("find_by_user_id.sql"),
		upsert:       mustReadTOTPRepositorySQL("upsert.sql"),
		deleteByUser: mustReadTOTPRepositorySQL("delete_by_user.sql"),
	}
}

func mustReadTOTPRepositorySQL(fileName string) string {
	data, err := totpRepositorySQLFS.ReadFile(path.Join("sql/totp_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load totp repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
