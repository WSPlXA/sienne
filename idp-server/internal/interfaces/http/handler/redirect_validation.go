package handler

import (
	"errors"
	"net/url"
	"strings"
)

var errInvalidLocalRedirectTarget = errors.New("invalid return_to")

func validateLocalRedirectTarget(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", nil
	}
	if strings.Contains(target, "\\") || strings.HasPrefix(target, "//") {
		return "", errInvalidLocalRedirectTarget
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", errInvalidLocalRedirectTarget
	}
	if u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return "", errInvalidLocalRedirectTarget
	}
	if !strings.HasPrefix(u.Path, "/") {
		return "", errInvalidLocalRedirectTarget
	}

	return u.String(), nil
}
