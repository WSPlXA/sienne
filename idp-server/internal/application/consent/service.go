package consent

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	clientdomain "idp-server/internal/domain/client"
	sessiondomain "idp-server/internal/domain/session"
	"idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
)

type Manager interface {
	Prepare(ctx context.Context, input PrepareInput) (*PrepareResult, error)
	Decide(ctx context.Context, input DecideInput) (*DecideResult, error)
}

type Service struct {
	clients      repository.ClientRepository
	sessions     repository.SessionRepository
	sessionCache cache.SessionCacheRepository
	consents     repository.ConsentRepository
	now          func() time.Time
}

func NewService(
	clients repository.ClientRepository,
	sessions repository.SessionRepository,
	sessionCache cache.SessionCacheRepository,
	consents repository.ConsentRepository,
) *Service {
	return &Service{
		clients:      clients,
		sessions:     sessions,
		sessionCache: sessionCache,
		consents:     consents,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (s *Service) Prepare(ctx context.Context, input PrepareInput) (*PrepareResult, error) {
	parsed, sessionModel, client, scopes, err := s.loadContext(ctx, input.ReturnTo, input.SessionID)
	if err != nil {
		return nil, err
	}
	_ = parsed
	_ = sessionModel

	return &PrepareResult{
		ClientID:   client.ClientID,
		ClientName: client.ClientName,
		Scopes:     scopes,
		ReturnTo:   input.ReturnTo,
	}, nil
}

func (s *Service) Decide(ctx context.Context, input DecideInput) (*DecideResult, error) {
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action != "accept" && action != "deny" {
		return nil, ErrInvalidAction
	}

	parsed, sessionModel, client, scopes, err := s.loadContext(ctx, input.ReturnTo, input.SessionID)
	if err != nil {
		return nil, err
	}

	if action == "deny" {
		redirectURI, err := buildDenyRedirect(parsed.redirectURI, parsed.state)
		if err != nil {
			return nil, ErrInvalidReturnTo
		}
		return &DecideResult{RedirectURI: redirectURI}, nil
	}

	if s.consents == nil {
		return nil, ErrInvalidClient
	}
	if err := s.consents.UpsertActiveConsent(ctx, sessionModel.UserID, client.ID, scopes, s.now()); err != nil {
		return nil, err
	}

	return &DecideResult{
		RedirectURI: input.ReturnTo,
	}, nil
}

type authorizeReturnTo struct {
	clientID    string
	redirectURI string
	scopes      []string
	state       string
}

func (s *Service) loadContext(ctx context.Context, returnTo, sessionID string) (*authorizeReturnTo, *sessiondomain.Model, *clientdomain.Model, []string, error) {
	parsed, err := parseAuthorizeReturnTo(returnTo)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, nil, nil, nil, ErrLoginRequired
	}

	if s.sessionCache != nil {
		cacheEntry, err := s.sessionCache.Get(ctx, sessionID)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if cacheEntry != nil {
			if cacheEntry.Status != "active" || !cacheEntry.ExpiresAt.After(s.now()) {
				return nil, nil, nil, nil, ErrLoginRequired
			}

			userID, err := strconv.ParseInt(cacheEntry.UserID, 10, 64)
			if err == nil && userID > 0 {
				client, err := s.clients.FindByClientID(ctx, parsed.clientID)
				if err != nil {
					return nil, nil, nil, nil, err
				}
				if client == nil || client.Status != "active" {
					return nil, nil, nil, nil, ErrInvalidClient
				}
				if !contains(client.RedirectURIs, parsed.redirectURI) {
					return nil, nil, nil, nil, ErrInvalidReturnTo
				}
				if !allContained(parsed.scopes, client.Scopes) {
					return nil, nil, nil, nil, ErrInvalidScope
				}

				return parsed, &sessiondomain.Model{
					SessionID:   sessionID,
					UserID:      userID,
					Subject:     cacheEntry.Subject,
					ExpiresAt:   cacheEntry.ExpiresAt,
					LoggedOutAt: nil,
				}, client, parsed.scopes, nil
			}
		}
	}

	sessionModel, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if sessionModel == nil || sessionModel.LoggedOutAt != nil || !sessionModel.ExpiresAt.After(s.now()) {
		return nil, nil, nil, nil, ErrLoginRequired
	}

	client, err := s.clients.FindByClientID(ctx, parsed.clientID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if client == nil || client.Status != "active" {
		return nil, nil, nil, nil, ErrInvalidClient
	}
	if !contains(client.RedirectURIs, parsed.redirectURI) {
		return nil, nil, nil, nil, ErrInvalidReturnTo
	}
	if !allContained(parsed.scopes, client.Scopes) {
		return nil, nil, nil, nil, ErrInvalidScope
	}

	return parsed, sessionModel, client, parsed.scopes, nil
}

func parseAuthorizeReturnTo(returnTo string) (*authorizeReturnTo, error) {
	returnTo = strings.TrimSpace(returnTo)
	if returnTo == "" {
		return nil, ErrInvalidReturnTo
	}

	u, err := url.Parse(returnTo)
	if err != nil {
		return nil, ErrInvalidReturnTo
	}
	if u.Path != "/oauth2/authorize" {
		return nil, ErrInvalidReturnTo
	}

	q := u.Query()
	clientID := strings.TrimSpace(q.Get("client_id"))
	redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
	if clientID == "" || redirectURI == "" {
		return nil, ErrInvalidReturnTo
	}

	scopes := normalizeScopes(strings.Fields(strings.TrimSpace(q.Get("scope"))))
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}

	return &authorizeReturnTo{
		clientID:    clientID,
		redirectURI: redirectURI,
		scopes:      scopes,
		state:       strings.TrimSpace(q.Get("state")),
	}, nil
}

func buildDenyRedirect(redirectURI, state string) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("error", "access_denied")
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func normalizeScopes(scopes []string) []string {
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	return result
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func allContained(values, allowed []string) bool {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		allowedSet[value] = struct{}{}
	}

	for _, value := range values {
		if _, ok := allowedSet[value]; !ok {
			return false
		}
	}
	return true
}
