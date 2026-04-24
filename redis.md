# Redis 数据清单（本项目）

本文按当前代码实现梳理本项目 Redis 中会出现的数据结构、字段、TTL 与用途。

## 1. 基础约定

- Redis key 统一前缀：`<prefix>:<env>:`  
  - `prefix` 来自 `REDIS_KEY_PREFIX`，默认 `idp`
  - `env` 来自 `APP_ENV`，默认 `dev`
- 运行数据库：`REDIS_DB`，默认 `0`
- 时间字段基本使用 RFC3339 字符串（如 `2026-04-14T12:00:00Z`）

## 2. 当前运行会出现的数据（Wire 已接入）

以下仓储在 `internal/bootstrap/wire.go` 已注册：session、token、device code、mfa、replay protection、rate limit。

### 2.1 Session 会话缓存

1. `"<prefix>:<env>:session:sid:<session_id>"`
- 类型：`Hash`
- 字段：
  - `user_id`
  - `subject`
  - `acr`
  - `amr_json`
  - `ip`
  - `user_agent`
  - `authenticated_at`
  - `expires_at`
  - `status`（常见 `active`）
- TTL：`SESSION_TTL`（默认 8h）
- 用途：按 `session_id` 直接命中会话，减少 DB 查询。

2. `"<prefix>:<env>:session:user:<user_id>"`
- 类型：`Set`
- 成员：`session_id`
- TTL：与该用户会话 TTL 对齐（至少不小于成员会话 TTL）
- 用途：按用户枚举会话，用于 `logout all`/管理员强制下线。

### 2.2 Token 缓存与撤销

3. `"<prefix>:<env>:token:access:sha256:<access_sha256>"`
- 类型：`Hash`
- 字段：
  - `client_id`
  - `user_id`
  - `subject`
  - `scopes_json`
  - `aud_json`
  - `token_type`
  - `token_format`
  - `issued_at`
  - `expires_at`
  - `revoked`（`"0"`/`"1"`）
- TTL：到 access token 过期（`time.Until(expires_at)`）
- 用途：快速 introspection/用户态校验元数据。

4. `"<prefix>:<env>:token:refresh:sha256:<refresh_sha256>"`
- 类型：`Hash`
- 常见字段（会随流程补充）：
  - `client_id`
  - `user_id`
  - `subject`
  - `scopes_json`
  - `issued_at`
  - `expires_at`
  - `status`（`active`/`rotated`/`compromised`）
  - `revoked`（`"0"`/`"1"`）
  - `family_id`
  - `rotated_to`
  - `rotated_from`（新 token 记录会写）
  - `rotated_at`
  - `grace_until`
  - `bind_fp`（重试指纹）
- TTL：到 refresh token 过期
- 用途：refresh rotation、并发重试宽限、replay 检测、家族级失效。

5. `"<prefix>:<env>:revoked:access:<access_sha256>"`
- 类型：`String`
- 值：`"1"`
- TTL：通常是 token 剩余有效期（退出登录时传入）
- 用途：高频拒绝检查（O(1) Exists）。

6. `"<prefix>:<env>:revoked:refresh:<refresh_sha256>"`
- 类型：`String`
- 值：`"1"`
- TTL：通常是 token 剩余有效期
- 用途：refresh token 即时撤销检查。

7. `"<prefix>:<env>:token:refresh:grace:<old_refresh_sha256>"`
- 类型：`String`
- 值：上一次成功刷新的完整 token 响应 JSON
- TTL：grace 窗口（当前常量 10 秒）
- 用途：并发刷新时，同窗口重试返回一致响应而非随机失败。

8. `"<prefix>:<env>:token:refresh:family:revoked:<family_id>"`
- 类型：`String`
- 值：`"1"`
- TTL：通常取旧 refresh key 的剩余 TTL（若不可得，回退 60 秒）
- 用途：检测到 replay/可疑重放后，按 token 家族封禁。

### 2.3 Device Authorization Grant

9. `"<prefix>:<env>:device:code:<device_code>"`
- 类型：`Hash`
- 字段：
  - `device_code`
  - `user_code`
  - `client_id`
  - `client_name`
  - `scopes_json`
  - `status`（`pending`/`approved`/`denied`/`consumed`）
  - `user_id`
  - `subject`
  - `expires_at`
  - `approved_at`
  - `denied_at`
  - `consumed_at`
  - `last_polled_at`
  - `interval`
- TTL：device code 生命周期（Wire 中默认 10 分钟）
- 用途：设备流核心状态机。

10. `"<prefix>:<env>:device:user:<user_code>"`
- 类型：`String`
- 值：`device_code`
- TTL：与对应 `device:code` 相同
- 用途：用户输入 `user_code` 时，O(1) 反查 `device_code`。

### 2.4 MFA 临时状态

11. `"<prefix>:<env>:mfa:totp:enroll:<session_id>"`
- 类型：`Hash`
- 字段：
  - `session_id`
  - `user_id`
  - `secret`
  - `provisioning_uri`
  - `expires_at`
- TTL：TOTP 绑定窗口（默认 10 分钟）
- 用途：TOTP 启用前的临时上下文（确认成功才落库）。

12. `"<prefix>:<env>:mfa:challenge:<challenge_id>"`
- 类型：`Hash`
- 字段：
  - `challenge_id`
  - `user_id`
  - `subject`
  - `username`
  - `ip_address`
  - `user_agent`
  - `return_to`
  - `redirect_uri`
  - `mfa_mode`
  - `push_status`
  - `push_code`
  - `approver_user_id`
  - `decided_at`
  - `passkey_session_json`
  - `expires_at`
- TTL：按流程设置
  - 登录二次验证常见 5 分钟
  - Passkey setup 常见 10 分钟
- 用途：登录第二要素挑战、Push/Passkey/TOTP 上下文承载。

13. `"<prefix>:<env>:mfa:totp:used:<user_id>:<purpose>:<step>"`
- 类型：`String`（`SETNX` 写 `"1"`）
- TTL：固定短窗（当前 120 秒）
- 用途：同一时间步 TOTP 防重放。

### 2.5 Federated OIDC 重放保护

14. `"<prefix>:<env>:oauthstate:<state>"`
- 类型：`Hash`
- 当前脚本实际写入字段：
  - `client_id`
  - `redirect_uri`
  - `session_id`
  - `created_at`
- TTL：`FEDERATED_OIDC_STATE_TTL`（默认 10 分钟）
- 用途：OIDC 登录 state 一次性上下文，回调时读取后删除。

15. `"<prefix>:<env>:nonce:<nonce>"`
- 类型：`String`（预期 `"1"`）
- TTL：调用方传入
- 用途：nonce 一次性保留（`SET NX`）。

说明：`oauthstate` 目前存在字段映射不一致。调用方写入的是 `nonce/return_to/redirect_uri/created_at`，而脚本按 `client_id/redirect_uri/session_id/created_at` 落盘，因此 `nonce` 与 `return_to` 不会按预期入 Redis。

### 2.6 登录失败计数与锁

16. `"<prefix>:<env>:loginfail:user:<username>"`
- 类型：`String`（整数计数）
- TTL：`LOGIN_FAILURE_WINDOW`（默认 15 分钟；首次 INCR 时设置）
- 用途：按用户名失败计数，触发用户锁策略。

17. `"<prefix>:<env>:loginfail:ip:<ip>"`
- 类型：`String`（整数计数）
- TTL：`LOGIN_FAILURE_WINDOW`（默认 15 分钟）
- 用途：按来源 IP 失败计数，触发 IP 锁策略。

18. `"<prefix>:<env>:lock:user:<user_id>"`
- 类型：`String`
- 值：`"1"`
- TTL：常见 `LOGIN_USER_LOCK_TTL`（默认 30 分钟）；也可能永久（不设 TTL）
- 用途：用户维度锁定哨兵。

19. `"<prefix>:<env>:lock:ip:<ip>"`
- 类型：`String`
- 值：`"1"`
- TTL：常见 `LOGIN_USER_LOCK_TTL`（默认 30 分钟）；也可能永久
- 用途：IP 维度锁定哨兵。

20. `"<prefix>:<env>:loginblacklist:user:<username>"`
- 类型：`String`（整数计数）
- TTL：当前实现为无 TTL（永久累计，直到显式 reset）
- 用途：长期黑名单计数，达到阈值后可触发永久锁用户。

## 3. 预留实现（代码存在，但默认主链路不落地）

### 3.1 Authorization Code 缓存（当前 Wire 未接入）

21. `"<prefix>:<env>:authcode:code:<code>"`
- 类型：`Hash`
- 字段：
  - `client_id`
  - `user_id`
  - `scope`
  - `expires_at`
  - `consumed`（`"0"`/`"1"`）
- TTL：调用 `Save` 传入
- 用途：授权码短时缓存 + 一次性消费控制。

22. `"<prefix>:<env>:authcode:consumed:<code>"`
- 类型：`String`
- 值：`"1"`
- TTL：通常跟授权码 TTL 同步
- 用途：快速 replay 标记。

### 3.2 刷新令牌可选索引（当前调用传空 key，不会创建）

23. `rotate_token.lua` 里支持可选 `user refresh set` / `client refresh set`（`Set`）
- 当前 Go 调用把这两个 key 传空字符串，Redis 不会产生这两类集合。

### 3.3 撤销时 introspection 缓存清理（当前未使用）

24. `revoke_token.lua` 支持传入 introspection cache key 做 `DEL`
- 当前 Go 调用该参数固定为空，不会产生或删除该类 key。

## 4. 结论（运维视角）

- 线上主要关注这几组 key：`session:*`、`token:*`、`revoked:*`、`device:*`、`mfa:*`、`loginfail:*`、`lock:*`、`loginblacklist:*`。
- TTL 最敏感的是：`session`、`token`、`device`、`mfa challenge`、`refresh grace`。
- 风险点：
  - `oauthstate` 字段映射与调用方不一致，可能导致联邦登录回调上下文缺字段。
  - `loginblacklist:user:*` 默认无 TTL，若不 reset 会持续增长。
