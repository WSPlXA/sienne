package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/jwk_key_repository/*.sql
var jwkKeyRepositorySQLFS embed.FS

type jwkKeyRepositorySQLSet struct {
	listCurrentKeys  string
	deactivateActive string
	insertActiveKey  string
}

var jwkKeyRepositorySQL = mustLoadJWKKeyRepositorySQL()

func mustLoadJWKKeyRepositorySQL() jwkKeyRepositorySQLSet {
	return jwkKeyRepositorySQLSet{
		listCurrentKeys:  mustReadJWKKeyRepositorySQL("list_current_keys.sql"),
		deactivateActive: mustReadJWKKeyRepositorySQL("deactivate_active_keys.sql"),
		insertActiveKey:  mustReadJWKKeyRepositorySQL("insert_active_key.sql"),
	}
}

func mustReadJWKKeyRepositorySQL(fileName string) string {
	data, err := jwkKeyRepositorySQLFS.ReadFile(path.Join("sql/jwk_key_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load jwk key repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
