package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/token_repository/*.sql
var tokenRepositorySQLFS embed.FS

// tokenRepositorySQLSet 把 SQL 文本在启动时一次性加载进内存。
// 这样仓储方法只关心“执行哪条语句”，避免在热路径上频繁读文件。
type tokenRepositorySQLSet struct {
	createAccessToken         string
	createRefreshToken        string
	findActiveAccessBySHA256  string
	findActiveRefreshBySHA256 string
	listActiveAccessByUserID  string
	listActiveRefreshByUserID string
	revokeAccessByUserID      string
	revokeRefreshByUserID     string
	rotateFindOldForUpdate    string
	rotateInsertNewRefresh    string
	rotateUpdateOldRefresh    string
}

var tokenRepositorySQL = mustLoadTokenRepositorySQL()

func mustLoadTokenRepositorySQL() tokenRepositorySQLSet {
	// 启动失败要早于处理请求失败，因此这里采用 must 风格：
	// 只要 SQL 文件缺失，就直接 panic 暴露打包问题。
	return tokenRepositorySQLSet{
		createAccessToken:         mustReadTokenRepositorySQL("create_access_token.sql"),
		createRefreshToken:        mustReadTokenRepositorySQL("create_refresh_token.sql"),
		findActiveAccessBySHA256:  mustReadTokenRepositorySQL("find_active_access_by_sha256.sql"),
		findActiveRefreshBySHA256: mustReadTokenRepositorySQL("find_active_refresh_by_sha256.sql"),
		listActiveAccessByUserID:  mustReadTokenRepositorySQL("list_active_access_by_user_id.sql"),
		listActiveRefreshByUserID: mustReadTokenRepositorySQL("list_active_refresh_by_user_id.sql"),
		revokeAccessByUserID:      mustReadTokenRepositorySQL("revoke_access_by_user_id.sql"),
		revokeRefreshByUserID:     mustReadTokenRepositorySQL("revoke_refresh_by_user_id.sql"),
		rotateFindOldForUpdate:    mustReadTokenRepositorySQL("rotate_find_old_for_update.sql"),
		rotateInsertNewRefresh:    mustReadTokenRepositorySQL("rotate_insert_new_refresh.sql"),
		rotateUpdateOldRefresh:    mustReadTokenRepositorySQL("rotate_update_old_refresh.sql"),
	}
}

func mustReadTokenRepositorySQL(fileName string) string {
	// TrimSpace 可以消除文件末尾换行带来的无意义差异，方便测试和日志输出。
	data, err := tokenRepositorySQLFS.ReadFile(path.Join("sql/token_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load token repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
