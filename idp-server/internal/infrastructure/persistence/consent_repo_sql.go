package persistence

import (
	"embed"
	"fmt"
	"path"
	"strings"
)

//go:embed sql/consent_repository/*.sql
var consentRepositorySQLFS embed.FS

type consentRepositorySQLSet struct {
	hasActiveConsentSelect string
	upsertSelectExisting   string
	upsertActiveConsent    string
}

var consentRepositorySQL = mustLoadConsentRepositorySQL()

func mustLoadConsentRepositorySQL() consentRepositorySQLSet {
	return consentRepositorySQLSet{
		hasActiveConsentSelect: mustReadConsentRepositorySQL("has_active_consent_select.sql"),
		upsertSelectExisting:   mustReadConsentRepositorySQL("upsert_select_existing.sql"),
		upsertActiveConsent:    mustReadConsentRepositorySQL("upsert_active_consent.sql"),
	}
}

func mustReadConsentRepositorySQL(fileName string) string {
	data, err := consentRepositorySQLFS.ReadFile(path.Join("sql/consent_repository", fileName))
	if err != nil {
		panic(fmt.Errorf("load consent repository sql %q: %w", fileName, err))
	}
	return strings.TrimSpace(string(data))
}
