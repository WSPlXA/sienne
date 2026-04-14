package handler

import (
	"errors"
	"net/url"
	"strings"
)

var errInvalidLocalRedirectTarget = errors.New("invalid return_to")

func validateLocalRedirectTarget(target string) (string, error) {
	// return_to 只允许站内相对路径，目的是彻底规避开放重定向。
	target = strings.TrimSpace(target)
	if target == "" {
		return "", nil
	}
	if strings.Contains(target, "\\") || strings.HasPrefix(target, "//") {
		// 这里显式拦住反斜杠和 scheme-relative URL，避免浏览器容错带来的绕过。
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
