package middleware

import "testing"

func TestSanitizeRequestPathKeepsAllowlistedQuery(t *testing.T) {
	path := sanitizeRequestPath("/oauth2/authorize", "scope=openid&client_id=demo&code=secret")
	want := "/oauth2/authorize?client_id=demo&scope=openid"
	if path != want {
		t.Fatalf("sanitizeRequestPath() = %q, want %q", path, want)
	}
}

func TestSanitizeRequestPathDropsSensitiveQuery(t *testing.T) {
	path := sanitizeRequestPath("/oauth2/callback", "code=secret&state=opaque")
	want := "/oauth2/callback"
	if path != want {
		t.Fatalf("sanitizeRequestPath() = %q, want %q", path, want)
	}
}
