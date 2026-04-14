package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/session_repository/*.sql
var sessionRepositorySQLFS embed.FS

// sessionRepositorySQLSet 负责集中保存 session 仓储使用到的 SQL 模板。
type sessionRepositorySQLSet struct {
	createSession      string
	findBySessionID    string
	listActiveByUserID string
	logoutBySessionID  string
	logoutAllByUserID  string
}

var sessionRepositorySQL = mustLoadSessionRepositorySQL()

func mustLoadSessionRepositorySQL() sessionRepositorySQLSet {
	// 和 token SQL 一样，session SQL 在启动时加载，确保部署包完整性尽早暴露。
	return sessionRepositorySQLSet{
		createSession:      mustReadSessionRepositorySQL("create_session.sql"),
		findBySessionID:    mustReadSessionRepositorySQL("find_by_session_id.sql"),
		listActiveByUserID: mustReadSessionRepositorySQL("list_active_by_user_id.sql"),
		logoutBySessionID:  mustReadSessionRepositorySQL("logout_by_session_id.sql"),
		logoutAllByUserID:  mustReadSessionRepositorySQL("logout_all_by_user_id.sql"),
	}
}

func mustReadSessionRepositorySQL(fileName string) string {
	// 统一裁掉首尾空白，避免 SQL 文件格式差异影响字符串比较。
	data, err := sessionRepositorySQLFS.ReadFile(path.Join("sql/session_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load session repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
