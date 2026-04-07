package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/session_repository/*.sql
var sessionRepositorySQLFS embed.FS

type sessionRepositorySQLSet struct {
	createSession      string
	findBySessionID    string
	listActiveByUserID string
	logoutBySessionID  string
	logoutAllByUserID  string
}

var sessionRepositorySQL = mustLoadSessionRepositorySQL()

func mustLoadSessionRepositorySQL() sessionRepositorySQLSet {
	return sessionRepositorySQLSet{
		createSession:      mustReadSessionRepositorySQL("create_session.sql"),
		findBySessionID:    mustReadSessionRepositorySQL("find_by_session_id.sql"),
		listActiveByUserID: mustReadSessionRepositorySQL("list_active_by_user_id.sql"),
		logoutBySessionID:  mustReadSessionRepositorySQL("logout_by_session_id.sql"),
		logoutAllByUserID:  mustReadSessionRepositorySQL("logout_all_by_user_id.sql"),
	}
}

func mustReadSessionRepositorySQL(fileName string) string {
	data, err := sessionRepositorySQLFS.ReadFile(path.Join("sql/session_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load session repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
