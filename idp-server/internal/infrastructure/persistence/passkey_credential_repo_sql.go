package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/passkey_credential_repository/*.sql
var passkeyCredentialRepositorySQLFS embed.FS

type passkeyCredentialRepositorySQLSet struct {
	listByUserID        string
	upsert              string
	touchByCredentialID string
}

var passkeyCredentialRepositorySQL = mustLoadPasskeyCredentialRepositorySQL()

func mustLoadPasskeyCredentialRepositorySQL() passkeyCredentialRepositorySQLSet {
	return passkeyCredentialRepositorySQLSet{
		listByUserID:        mustReadPasskeyCredentialRepositorySQL("list_by_user_id.sql"),
		upsert:              mustReadPasskeyCredentialRepositorySQL("upsert.sql"),
		touchByCredentialID: mustReadPasskeyCredentialRepositorySQL("touch_by_credential_id.sql"),
	}
}

func mustReadPasskeyCredentialRepositorySQL(fileName string) string {
	data, err := passkeyCredentialRepositorySQLFS.ReadFile(path.Join("sql/passkey_credential_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load passkey credential repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
