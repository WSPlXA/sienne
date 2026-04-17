package device

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	cacheport "idp-server/internal/ports/cache"
	"idp-server/internal/ports/repository"
)

type Service struct {
	clients      repository.ClientRepository
	deviceCodes  cacheport.DeviceCodeRepository
	sessions     repository.SessionRepository
	sessionCache cacheport.SessionCacheRepository
	deviceTTL    time.Duration
	interval     time.Duration
	now          func() time.Time
}

func NewService(
	clients repository.ClientRepository,
	deviceCodes cacheport.DeviceCodeRepository,
	sessions repository.SessionRepository,
	sessionCache cacheport.SessionCacheRepository,
	deviceTTL time.Duration,
	interval time.Duration,
) *Service {
	return &Service{
		clients:      clients,
		deviceCodes:  deviceCodes,
		sessions:     sessions,
		sessionCache: sessionCache,
		deviceTTL:    deviceTTL,
		interval:     interval,
		now: func() time.Time {
			return time.Now().UTC()
		},
	}
}

func (s *Service) Start(ctx context.Context, input StartInput) (*StartResult, error) {
	// Start 是 OAuth 2.0 Device Authorization Grant 的起点：
	// 为受限输入设备生成 device_code / user_code，并把待授权状态写入缓存。
	client, err := s.clients.FindByClientID(ctx, strings.TrimSpace(input.ClientID))
	if err != nil {
		return nil, err
	}
	if client == nil || client.Status != "active" || !contains(client.GrantTypes, "urn:ietf:params:oauth:grant-type:device_code") {
		return nil, ErrInvalidClient
	}

	scopes := normalizeScopes(input.Scopes)
	if len(scopes) == 0 {
		// 设备流未显式传 scope 时，默认给客户端允许的全部 scope。
		scopes = append([]string(nil), client.Scopes...)
	}
	if !allContained(scopes, client.Scopes) {
		return nil, ErrInvalidScope
	}

	deviceCode, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	userCode, err := randomUserCode()
	if err != nil {
		return nil, err
	}
	scopeJSON, _ := json.Marshal(scopes)
	expiresAt := s.now().Add(s.deviceTTL)
	// device_code 给轮询 token 端点使用，user_code 给用户在浏览器里手动输入确认。
	if err := s.deviceCodes.Save(ctx, cacheport.DeviceCodeEntry{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   client.ClientID,
		ClientName: client.ClientName,
		ScopesJSON: string(scopeJSON),
		Status:     "pending",
		ExpiresAt:  expiresAt,
		Interval:   int64(s.interval / time.Second),
	}, s.deviceTTL); err != nil {
		return nil, err
	}

	return &StartResult{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ExpiresAt:  expiresAt,
		Interval:   int64(s.interval / time.Second),
		ClientID:   client.ClientID,
	}, nil
}

func (s *Service) Prepare(ctx context.Context, input PrepareInput) (*PrepareResult, error) {
	// Prepare 用于浏览器确认页展示，把 user_code 映射回 client 和 scope 信息。
	entry, _, _, err := s.loadContext(ctx, input.SessionID, input.UserCode)
	if err != nil {
		return nil, err
	}

	scopes := decodeScopes(entry.ScopesJSON)
	return &PrepareResult{
		UserCode:   entry.UserCode,
		ClientID:   entry.ClientID,
		ClientName: entry.ClientName,
		Scopes:     scopes,
	}, nil
}

func (s *Service) Decide(ctx context.Context, input DecideInput) (*DecideResult, error) {
	// Decide 由用户在浏览器里明确批准或拒绝，
	// 结果会回写到 device code 记录，供设备轮询消费。
	action := strings.ToLower(strings.TrimSpace(input.Action))
	if action != "approve" && action != "deny" {
		return nil, ErrInvalidAction
	}

	entry, sessionUserID, subject, err := s.loadContext(ctx, input.SessionID, input.UserCode)
	if err != nil {
		return nil, err
	}
	if action == "deny" {
		// 拒绝时不需要绑定用户身份，直接把状态记为 denied。
		if err := s.deviceCodes.Deny(ctx, entry.UserCode, s.now()); err != nil {
			return nil, err
		}
		return &DecideResult{Approved: false}, nil
	}

	if err := s.deviceCodes.Approve(ctx, entry.UserCode, strconv.FormatInt(sessionUserID, 10), subject, s.now()); err != nil {
		return nil, err
	}
	return &DecideResult{Approved: true}, nil
}

func (s *Service) loadContext(ctx context.Context, sessionID string, userCode string) (*cacheport.DeviceCodeEntry, int64, string, error) {
	// 设备确认页既要验证 user_code 仍然有效，也要确认当前浏览器里确实有登录态。
	userCode = strings.ToUpper(strings.TrimSpace(userCode))
	if userCode == "" {
		return nil, 0, "", ErrInvalidUserCode
	}
	if s.deviceCodes == nil {
		return nil, 0, "", ErrInvalidUserCode
	}
	entry, err := s.deviceCodes.GetByUserCode(ctx, userCode)
	if err != nil {
		return nil, 0, "", err
	}
	if entry == nil || !entry.ExpiresAt.After(s.now()) || (entry.Status != "" && entry.Status != "pending") {
		return nil, 0, "", ErrInvalidUserCode
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, 0, "", ErrLoginRequired
	}

	if s.sessionCache != nil {
		// 会话缓存命中时可以避免每次确认页加载都打数据库。
		cacheEntry, err := s.sessionCache.Get(ctx, sessionID)
		if err != nil {
			return nil, 0, "", err
		}
		if cacheport.IsSessionEntryActive(cacheEntry, s.now()) {
			userID, err := strconv.ParseInt(cacheEntry.UserID, 10, 64)
			if err == nil && userID > 0 {
				return entry, userID, cacheEntry.Subject, nil
			}
		}
	}

	sessionModel, err := s.sessions.FindBySessionID(ctx, sessionID)
	if err != nil {
		return nil, 0, "", err
	}
	if sessionModel == nil || sessionModel.LoggedOutAt != nil || !sessionModel.ExpiresAt.After(s.now()) {
		return nil, 0, "", ErrLoginRequired
	}
	return entry, sessionModel.UserID, sessionModel.Subject, nil
}

func decodeScopes(raw string) []string {
	// scope 在缓存里按 JSON 数组保存，这里给展示层解码成人类可读切片。
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var scopes []string
	if err := json.Unmarshal([]byte(raw), &scopes); err != nil {
		return nil
	}
	return scopes
}

func normalizeScopes(scopes []string) []string {
	// 与 authorize 流一致，去空、去重并保留输入顺序。
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

func randomToken(length int) (string, error) {
	// device_code 使用较长随机串，核心目标是高熵和不可猜测。
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, length)
	for i := range buf {
		out[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(out), nil
}

func randomUserCode() (string, error) {
	// user_code 面向人工输入，字符集刻意去掉易混淆字符（如 0/O、1/I）。
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, len(buf))
	for i := range buf {
		out[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return fmt.Sprintf("%s-%s", string(out[:4]), string(out[4:])), nil
}
