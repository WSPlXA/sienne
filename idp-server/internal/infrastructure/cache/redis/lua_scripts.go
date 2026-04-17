package redis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	goredis "github.com/redis/go-redis/v9"
)

type scriptSet struct {
	saveSession              *goredis.Script
	saveMFAChallenge         *goredis.Script
	deleteSession            *goredis.Script
	consumeAuthorizationCode *goredis.Script
	saveOAuthState           *goredis.Script
	reserveNonce             *goredis.Script
	incrementWithTTL         *goredis.Script
	revokeToken              *goredis.Script
	checkRefreshReplay       *goredis.Script
	rotateToken              *goredis.Script
}

var (
	scriptsOnce      sync.Once
	scriptsSingleton *scriptSet
	scriptsErr       error
)

func loadScripts() (*scriptSet, error) {
	scriptsOnce.Do(func() {
		scriptsSingleton = &scriptSet{
			saveSession:              mustLoadScript("save_session.lua"),
			saveMFAChallenge:         mustLoadScript("save_mfa_challenge.lua"),
			deleteSession:            mustLoadScript("delete_session.lua"),
			consumeAuthorizationCode: mustLoadScript("consume_authorization_code.lua"),
			saveOAuthState:           mustLoadScript("save_oauth_state.lua"),
			reserveNonce:             mustLoadScript("reserve_nonce.lua"),
			incrementWithTTL:         mustLoadScript("increment_with_ttl.lua"),
			revokeToken:              mustLoadScript("revoke_token.lua"),
			checkRefreshReplay:       mustLoadScript("check_refresh_replay.lua"),
			rotateToken:              mustLoadScript("rotate_token.lua"),
		}
	})
	return scriptsSingleton, scriptsErr
}

func mustLoadScript(name string) *goredis.Script {
	content, err := readLuaScript(name)
	if err != nil {
		panic(err)
	}
	return goredis.NewScript(content)
}

func readLuaScript(name string) (string, error) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("resolve current file for lua script %q", name)
	}

	scriptPath := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../../../../scripts/lua", name))
	content, err := os.ReadFile(scriptPath)
	if err != nil {
		return "", fmt.Errorf("read lua script %q: %w", scriptPath, err)
	}

	return string(content), nil
}

func runScript(ctx context.Context, script *goredis.Script, rdb goredis.Scripter, keys []string, args ...any) *goredis.Cmd {
	cmd := script.Run(ctx, rdb, keys, args...)
	if err := cmd.Err(); err != nil {
		cmd.SetErr(&LuaScriptError{ScriptSHA: script.Hash(), Err: err})
	}
	return cmd
}

func PreloadScripts(ctx context.Context, rdb *goredis.Client) error {
	scripts, err := loadScripts()
	if err != nil {
		return err
	}

	for _, script := range []*goredis.Script{
		scripts.saveSession,
		scripts.saveMFAChallenge,
		scripts.deleteSession,
		scripts.consumeAuthorizationCode,
		scripts.saveOAuthState,
		scripts.reserveNonce,
		scripts.incrementWithTTL,
		scripts.revokeToken,
		scripts.checkRefreshReplay,
		scripts.rotateToken,
	} {
		if err := script.Load(ctx, rdb).Err(); err != nil {
			return &LuaScriptError{ScriptSHA: script.Hash(), Err: err}
		}
	}
	return nil
}

type LuaScriptError struct {
	ScriptSHA string
	Err       error
}

func (e *LuaScriptError) Error() string {
	return fmt.Sprintf("redis lua script sha=%s: %v", e.ScriptSHA, e.Err)
}

func (e *LuaScriptError) Unwrap() error {
	return e.Err
}
