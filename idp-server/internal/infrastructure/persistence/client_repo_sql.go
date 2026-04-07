package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/client_repository/*.sql
var clientRepositorySQLFS embed.FS

type clientRepositorySQLSet struct {
	createClient                      string
	findByClientID                    string
	selectRedirectURIsByClientID      string
	selectGrantTypesByClientID        string
	selectAuthMethodsByClientID       string
	selectScopesByClientID            string
	insertClientGrantType             string
	insertClientAuthMethod            string
	insertClientScope                 string
	insertRedirectURIIgnore           string
	hasPostLogoutRedirectURI          string
	insertPostLogoutRedirectURIIgnore string
	insertRedirectURI                 string
	insertPostLogoutRedirectURI       string
}

var clientRepositorySQL = mustLoadClientRepositorySQL()

func mustLoadClientRepositorySQL() clientRepositorySQLSet {
	return clientRepositorySQLSet{
		createClient:                      mustReadClientRepositorySQL("create_client.sql"),
		findByClientID:                    mustReadClientRepositorySQL("find_by_client_id.sql"),
		selectRedirectURIsByClientID:      mustReadClientRepositorySQL("select_redirect_uris_by_client_id.sql"),
		selectGrantTypesByClientID:        mustReadClientRepositorySQL("select_grant_types_by_client_id.sql"),
		selectAuthMethodsByClientID:       mustReadClientRepositorySQL("select_auth_methods_by_client_id.sql"),
		selectScopesByClientID:            mustReadClientRepositorySQL("select_scopes_by_client_id.sql"),
		insertClientGrantType:             mustReadClientRepositorySQL("insert_client_grant_type.sql"),
		insertClientAuthMethod:            mustReadClientRepositorySQL("insert_client_auth_method.sql"),
		insertClientScope:                 mustReadClientRepositorySQL("insert_client_scope.sql"),
		insertRedirectURIIgnore:           mustReadClientRepositorySQL("insert_redirect_uri_ignore.sql"),
		hasPostLogoutRedirectURI:          mustReadClientRepositorySQL("has_post_logout_redirect_uri.sql"),
		insertPostLogoutRedirectURIIgnore: mustReadClientRepositorySQL("insert_post_logout_redirect_uri_ignore.sql"),
		insertRedirectURI:                 mustReadClientRepositorySQL("insert_redirect_uri.sql"),
		insertPostLogoutRedirectURI:       mustReadClientRepositorySQL("insert_post_logout_redirect_uri.sql"),
	}
}

func mustReadClientRepositorySQL(fileName string) string {
	data, err := clientRepositorySQLFS.ReadFile(path.Join("sql/client_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load client repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
