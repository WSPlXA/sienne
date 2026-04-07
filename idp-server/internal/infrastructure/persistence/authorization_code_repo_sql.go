package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/authorization_code_repository/*.sql
var authorizationCodeRepositorySQLFS embed.FS

type authorizationCodeRepositorySQLSet struct {
	createAuthorizationCode      string
	consumeSelectByCodeForUpdate string
	consumeUpdateConsumedAt      string
}

var authorizationCodeRepositorySQL = mustLoadAuthorizationCodeRepositorySQL()

func mustLoadAuthorizationCodeRepositorySQL() authorizationCodeRepositorySQLSet {
	return authorizationCodeRepositorySQLSet{
		createAuthorizationCode:      mustReadAuthorizationCodeRepositorySQL("create_authorization_code.sql"),
		consumeSelectByCodeForUpdate: mustReadAuthorizationCodeRepositorySQL("consume_select_by_code_for_update.sql"),
		consumeUpdateConsumedAt:      mustReadAuthorizationCodeRepositorySQL("consume_update_consumed_at.sql"),
	}
}

func mustReadAuthorizationCodeRepositorySQL(fileName string) string {
	data, err := authorizationCodeRepositorySQLFS.ReadFile(path.Join("sql/authorization_code_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load authorization code repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
