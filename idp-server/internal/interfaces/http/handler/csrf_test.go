package handler

import (
	"net/http"
	"testing"
)

func mustNewCSRFCookie(t *testing.T) (*http.Cookie, string) {
	t.Helper()

	token, err := newCSRFToken()
	if err != nil {
		t.Fatalf("new csrf token: %v", err)
	}

	return &http.Cookie{Name: csrfCookieName, Value: token}, token
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
