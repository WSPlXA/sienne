package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/token_repository/*.sql
var tokenRepositorySQLFS embed.FS

type tokenRepositorySQLSet struct {
	createAccessToken         string
	createRefreshToken        string
	findActiveAccessBySHA256  string
	findActiveRefreshBySHA256 string
	rotateFindOldForUpdate    string
	rotateInsertNewRefresh    string
	rotateUpdateOldRefresh    string
}

var tokenRepositorySQL = mustLoadTokenRepositorySQL()

func mustLoadTokenRepositorySQL() tokenRepositorySQLSet {
	return tokenRepositorySQLSet{
		createAccessToken:         mustReadTokenRepositorySQL("create_access_token.sql"),
		createRefreshToken:        mustReadTokenRepositorySQL("create_refresh_token.sql"),
		findActiveAccessBySHA256:  mustReadTokenRepositorySQL("find_active_access_by_sha256.sql"),
		findActiveRefreshBySHA256: mustReadTokenRepositorySQL("find_active_refresh_by_sha256.sql"),
		rotateFindOldForUpdate:    mustReadTokenRepositorySQL("rotate_find_old_for_update.sql"),
		rotateInsertNewRefresh:    mustReadTokenRepositorySQL("rotate_insert_new_refresh.sql"),
		rotateUpdateOldRefresh:    mustReadTokenRepositorySQL("rotate_update_old_refresh.sql"),
	}
}

func mustReadTokenRepositorySQL(fileName string) string {
	data, err := tokenRepositorySQLFS.ReadFile(path.Join("sql/token_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load token repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
