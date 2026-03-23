# idp-server

API端点有如下设置

- `POST /register`
- `POST /login`
- `GET /oauth2/authorize`
- `POST /oauth2/token` 的 `authorization_code`
- `POST /oauth2/token` 的 `refresh_token`
- `POST /oauth2/token` 的 `client_credentials`
- `POST /oauth2/clients`
- `POST /oauth2/clients/:client_id/redirect-uris`
- `GET /oauth2/userinfo`
- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`
- Redis Lua 脚本预热与执行

`/oauth2/authorize` 有如下设置：

- 校验 `response_type=code`
- 校验 client 是否存在、是否激活、是否允许 `authorization_code`
- 校验 `redirect_uri`
- 校验请求 scope 是否在 client 允许范围内
- 校验 PKCE 参数
- 校验 `idp_session` 对应的登录 session 是否有效
- 在满足条件时签发新的 authorization code 并重定向回 client

`/consent` 有如下动作：

- 当 client 要求 consent 且当前 scope 还没被授权时，`/oauth2/authorize` 会跳到 `/consent?return_to=...`
- `GET /consent` 会返回一个 HTML consent 页面
- 如果请求头更偏 API 调试，也可以继续拿到当前 client 和待授权 scopes
- `POST /consent` 支持 `action=accept` 或 `action=deny`
- `accept` 会落库 consent 并跳回原始 authorize 请求
- `deny` 会跳回 client `redirect_uri` 并带上 `error=access_denied`

OIDC 元数据端点也已经开放：

- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`

当授权请求包含 `openid` scope 时，`POST /oauth2/token` 现在也会返回真正的 `id_token`。当前 `id_token` 已包含这些 OIDC 关键 claims：

- `iss`
- `sub`
- `aud`
- `exp`
- `iat`
- `auth_time`
- `nonce`
- `azp`
- `name`
- `preferred_username`
- `email`
- `email_verified`

## 运行依赖

- Go 1.24+
- MySQL 8
- Redis 7+

## 初始化数据库

推荐直接用 `make`：

```bash
make migrate
```

如果你的 MySQL 跑在容器里，更方便的是：

```bash
make migrate-docker
```

底层执行的就是 [migrate.sql](/workspace/idp-server/scripts/migrate.sql)。

## 环境变量

服务启动时会优先读取完整地址配置；如果没提供，会按主机名形式自动拼装。

### MySQL

二选一：

- `MYSQL_DSN`
- 或者同时提供：
  - `MYSQL_HOST`
  - `MYSQL_DATABASE`
  - `MYSQL_USER`
  - `MYSQL_PASSWORD`
  - `MYSQL_PORT` 可选，默认 `3306`

### Redis

二选一：

- `REDIS_ADDR`
- 或者：
  - `REDIS_HOST`
  - `REDIS_PORT` 可选，默认 `6379`

### Redis 在项目里的作用

Redis 在这个项目里不是“可有可无的普通缓存”，而是 OAuth2 / OIDC 流程里的高速状态层，主要存放带 TTL、需要快速判断、适合原子更新的数据。

当前已经接入主流程的用途包括：

- 登录 session cache：登录成功后会把 session 写入 Redis，同时维护用户到 session 的索引，便于快速校验、查找和删除登录态
- token cache：缓存 access token / refresh token 的摘要、过期时间、撤销标记和 refresh rotation 状态
- token revoke / refresh rotation：用 Redis Lua 脚本做原子撤销和 refresh token 轮换，避免并发下状态不一致

仓库里已经实现、但目前还没有完全接入主流程的能力包括：

- authorization code 一次性消费缓存
- OAuth `state` / OIDC `nonce` 防重放
- 登录失败计数与临时锁定

可以把它理解成：

- MySQL 更像持久化真相源，存业务主数据
- Redis 更像安全流程里的临时状态层，负责高频读写、短期状态和原子控制

### MySQL / Redis 请求流转图

下面这张图把当前实现里登录、授权码、token 刷新三条链路串起来了。可以先抓住一个大方向：

- 登录态和 token 临时状态主要借助 Redis 提速与做原子控制
- 用户、client、authorization code、refresh token 的持久化真相仍然主要在 MySQL

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser / Client
    participant A as authn service
    participant Z as authz service
    participant T as token service
    participant M as MySQL
    participant R as Redis

    Note over B,R: 1. 登录
    B->>A: POST /login
    A->>M: 查询 users / 校验密码
    M-->>A: 用户与密码校验结果
    A->>M: 写入 login_sessions
    A->>R: 写入 session cache 与用户 session 索引
    A-->>B: 返回 idp_session cookie

    Note over B,R: 2. 授权码
    B->>Z: GET /oauth2/authorize + idp_session
    Z->>M: 查询 oauth_clients
    Z->>M: 查询 login_sessions
    Z->>M: 查询 consents
    Z->>M: 写入 authorization_codes
    Z-->>B: 302 redirect with code

    Note over B,R: 3. 用 code 换 token
    B->>T: POST /oauth2/token (authorization_code)
    T->>M: 查询 oauth_clients
    T->>M: 消费 authorization_codes
    T->>M: 查询 users
    T->>M: 写入 access_tokens
    T->>M: 写入 refresh_tokens
    T->>R: 写入 access token cache
    T->>R: 写入 refresh token cache
    T-->>B: 返回 access_token / refresh_token / id_token

    Note over B,R: 4. refresh token 轮换
    B->>T: POST /oauth2/token (refresh_token)
    T->>M: 查询 oauth_clients
    T->>M: 查询有效 refresh_tokens
    T->>M: 查询 users
    T->>M: 写入 access_tokens
    T->>M: 轮换 refresh_tokens\n旧 token revoked_at + 新 token 写入
    T->>R: rotate_token.lua 原子轮换
    R-->>T: 新 refresh token cache + 旧 revoke marker
    T-->>B: 返回新 access_token / refresh_token
```

结合当前代码，三条链路的分工大致是：

- 登录：先查 MySQL 用户与密码，成功后把 session 同时写入 MySQL 和 Redis
- 授权码：`/oauth2/authorize` 当前主要查 MySQL 里的 client、session、consent，并把 authorization code 持久化到 MySQL
- 用 code 换 token：先消费 MySQL 中的 authorization code，再签发 token；access token / refresh token 会同时写 MySQL 和 Redis
- 刷新 token：旧 refresh token 的有效性与轮换结果以 MySQL 为准，Redis 用来缓存新 token 状态并通过 Lua 脚本原子写入撤销标记

当前仓库里也已经有 authorization code cache、`state` / `nonce` 防重放、登录失败计数这些 Redis 组件，但还没有全部接进主流程，所以图里按“当前实际主链路”画成了 MySQL 主导。

### 其他可选配置

- `REDIS_PASSWORD`
- `REDIS_DB`，默认 `0`
- `REDIS_KEY_PREFIX`，默认 `idp`
- `APP_ENV`，默认 `dev`
- `SESSION_TTL`，默认 `8h`
- `ISSUER`，默认 `http://localhost:8080`
- `JWT_KEY_ID`，默认 `kid-2026-01-rs256`
- `LISTEN_ADDR`，默认 `:8080`

## 按你当前环境启动

如果你现在的环境变量是：

```bash
export REDIS_HOST=redis
export MYSQL_HOST=db
export MYSQL_DATABASE=app
export MYSQL_USER=app
export MYSQL_PASSWORD=apppass
```

再补几个推荐值：

```bash
export APP_ENV=dev
export ISSUER=http://localhost:8080
export LISTEN_ADDR=:8080
```

可以先看一眼当前会用到的配置：

```bash
make env
```

然后直接启动：

```bash
make run
```

健康检查：

```bash
curl http://localhost:8080/healthz
```

## 当前可用的测试账号和客户端

这些 fixture 都来自 [migrate.sql](/workspace/idp-server/scripts/migrate.sql)。

### 用户

- `alice / alice123`
- `bob / bob123`
- `locked_user / locked123`

### OAuth Client

- `web-client / secret123`
- `mobile-public-client / (public client，无 client secret)`
- `service-client / service123`

### 授权码联调夹具

- `code`: `sample_auth_code_abc123`
- `redirect_uri`: `http://localhost:8081/callback`
- `code_verifier`: `verifier123`
- `seed session cookie`: `idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`

## 接口说明

### 1. 注册

支持完整注册接口：

- 校验用户名格式
- 校验邮箱格式
- 校验显示名长度
- 校验密码强度
- 检查用户名唯一性
- 检查邮箱唯一性
- 使用 `PasswordVerifier.HashPassword(...)` 生成 bcrypt hash
- 写入 `users`

真正注册使用 `POST /register`。

示例：

```bash
curl -i \
  -X POST http://localhost:8080/register \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "charlie01",
    "email": "charlie01@example.com",
    "display_name": "Charlie One",
    "password": "charlie123"
  }'
```

成功后返回 `201 Created`，并带回新用户的基础信息。

当前密码策略是：

- 长度 `8-128`
- 至少包含一个字母
- 至少包含一个数字

冲突和校验失败时：

- 用户名/邮箱已存在：`409 Conflict`
- 格式不合法或密码太弱：`400 Bad Request`

### 2. 登录

`GET /login` 现在同时支持两种模式：

- 浏览器访问时返回一个可直接提交的 HTML 登录页
- API 调试时继续返回 JSON 提示

真正提交登录仍然使用 `POST /login`。

示例：

```bash
curl -i \
  -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "alice",
    "password": "alice123"
  }'
```

成功后会：

- 返回 `session_id`
- 设置 `idp_session` Cookie
- 写入 MySQL `login_sessions`
- 写入 Redis session cache 和用户 session 索引

### 2.1 OAuth Client 管理

现在已经支持通过 HTTP 直接创建 OAuth client，并在后续为它追加 redirect URI。

`POST /oauth2/clients` 会一次性写入这些表：

- `oauth_clients`
- `oauth_client_grant_types`
- `oauth_client_auth_methods`
- `oauth_client_scopes`
- `oauth_client_redirect_uris`（当请求里带了 `redirect_uris` 且 grant 包含 `authorization_code` 时）

创建一个 confidential web client：

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/clients \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "demo-web-client",
    "client_name": "Demo Web Client",
    "client_secret": "super-secret-1",
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "offline_access"],
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

创建一个 service client：

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/clients \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "demo-service-client",
    "client_name": "Demo Service Client",
    "client_secret": "service-secret-1",
    "grant_types": ["client_credentials"],
    "scopes": ["internal.api.read", "internal.api.write"]
  }'
```

当前的创建规则包括：

- `client_type` 默认是 `confidential`
- `confidential` 默认 `token_endpoint_auth_method=client_secret_basic`
- `public` 默认 `token_endpoint_auth_method=none`
- `public` client 必须启用 PKCE
- `client_credentials` 只允许配置在 `confidential` client 上
- `authorization_code` client 必须提供至少一个合法 `redirect_uri`

如果你只是想给现有 client 追加回调地址，可以用：

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/clients/demo-web-client/redirect-uris \
  -H 'Content-Type: application/json' \
  -d '{
    "redirect_uris": [
      "http://localhost:3000/callback",
      "http://localhost:5173/callback"
    ]
  }'
```

这个端点是幂等的；重复注册同一个 URI 会被跳过，不会重复写入。

### 3. 用 authorization code 换 token

当前最容易联调的方式是直接使用 seed 里的 sample code：

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/token \
  -u web-client:secret123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'code=sample_auth_code_abc123' \
  -d 'redirect_uri=http://localhost:8081/callback' \
  -d 'code_verifier=verifier123'
```

成功后会返回：

- `access_token`
- `refresh_token`
- `token_type`
- `expires_in`
- `scope`

### 3.1 真实走一遍 authorize

如果你想确认 `/oauth2/authorize` 现在已经会真实发 code，最快的方式是直接带 seed 里的 session cookie：

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  'http://localhost:8080/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid%20profile%20email&state=demo-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

成功时会返回 `302`，并跳到：

```text
http://localhost:8081/callback?code=...&state=demo-state
```

我已经按这条路径做过一次真实联调，随后再用返回的 `code` 调 `/oauth2/token`，换 token 成功。

### 3.2 未登录时的行为

如果你没有带 `idp_session`，`/oauth2/authorize` 会先把你重定向到 `/login`，并自动附带 `return_to`：

```text
/login?return_to=/oauth2/authorize?...
```

登录成功后，`POST /login` 现在会在设置 `idp_session` cookie 后跳回原始 authorize URL。

### 3.3 consent 流程

如果你请求的 scope 超过了当前已授权范围，例如加上 `offline_access`，`/oauth2/authorize` 会先跳到 `/consent`：

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  'http://localhost:8080/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid%20profile%20email%20offline_access&state=consent-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

这时返回会是：

```text
Location: /consent?return_to=...
```

查看 consent 内容：

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  'http://localhost:8080/consent?return_to=/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid%20profile%20email%20offline_access&state=consent-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

如果你是直接用浏览器打开这个 URL，现在会看到一个真正的 consent 页面，而不是纯 JSON。

接受授权：

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  -X POST http://localhost:8080/consent \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'action=accept' \
  --data-urlencode 'return_to=/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid profile email offline_access&state=consent-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

拒绝授权：

```bash
curl -i \
  --cookie 'idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' \
  -X POST http://localhost:8080/consent \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'action=deny' \
  --data-urlencode 'return_to=/oauth2/authorize?response_type=code&client_id=web-client&redirect_uri=http://localhost:8081/callback&scope=openid profile email offline_access&state=deny-state&code_challenge=Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ&code_challenge_method=S256'
```

`deny` 时会跳回：

```text
http://localhost:8081/callback?error=access_denied&state=deny-state
```

### 4. 用 refresh token 轮换

把上一步返回的 `refresh_token` 带上：

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/token \
  -u web-client:secret123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d 'refresh_token=REPLACE_WITH_REFRESH_TOKEN'
```

当前实现会真正做 refresh token rotation：

- 旧 refresh token 在 MySQL 中写入 `revoked_at`
- 新 refresh token 被创建
- Redis 中执行 `rotate_token.lua`
- 旧 token 的 revoke marker 会被写入 Redis

### 4.1 用 client_credentials 换 token

对于 service client，可以直接走 `client_credentials`：

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/token \
  -u service-client:service123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'scope=internal.api.read'
```

成功后会返回：

- `access_token`
- `token_type`
- `expires_in`
- `scope`

当前实现里：

- 如果不传 `scope`，默认会下发该 client 允许的全部 scopes
- 如果请求了未被该 client 授权的 scope，会返回 `invalid_scope`
- `client_credentials` 不会返回 `refresh_token`

### 5. 获取 userinfo

把 `access_token` 作为 Bearer token 带上：

```bash
curl -i \
  http://localhost:8080/oauth2/userinfo \
  -H 'Authorization: Bearer REPLACE_WITH_ACCESS_TOKEN'
```

成功返回类似：

```json
{
  "sub": "11111111-1111-1111-1111-111111111111",
  "name": "Alice",
  "preferred_username": "alice",
  "email": "alice@example.com",
  "email_verified": true
}
```

### 6. OIDC Discovery

Discovery 文档：

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

当前会返回这些核心字段：

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `userinfo_endpoint`
- `jwks_uri`
- `response_types_supported`
- `grant_types_supported`
- `code_challenge_methods_supported`

### 7. JWKS

公开 JWK 集：

```bash
curl http://localhost:8080/oauth2/jwks
```

当前会返回运行时 RSA signing key 对应的公钥，字段包括：

- `kty`
- `kid`
- `use`
- `alg`
- `n`
- `e`

## Signing Key 持久化

现在这版已经不再默认依赖“进程启动时临时生成 key”来支撑 discovery / JWKS。

当前启动流程会优先：

1. 从 MySQL 的 `jwk_keys` 读取当前可用 key 元数据
2. 根据 `private_key_ref` 加载真实私钥
3. 用加载到的 active signing key 进行 JWT 签发
4. 用 `jwk_keys` 中的公开 JWK 构建 `/oauth2/jwks`
5. 周期检查 active key 的 `rotates_at`，在进入 rotation 窗口时自动生成下一把 key
6. 将旧 active key 退役为非 active，并保留一段可验证旧 token 的公开 key 生命周期

当前支持的 `private_key_ref` 形式：

- `file://relative/or/absolute/path`
- `env://ENV_VAR_NAME`
- `vault://path/to/key`
- `kms://key/name`

开发环境里，seed 已经内置了一把稳定 dev key：

- `kid`: `kid-2026-01-rs256`
- `private_key_ref`: `file://scripts/dev_keys/kid-2026-01-rs256.pem`

这意味着：

- 服务重启后 `kid` 不会漂移
- `/.well-known/openid-configuration` 和 `/oauth2/jwks` 会稳定返回同一把 seed key
- 新签发的 JWT 头会带稳定的 `kid`
- 当 active key 接近 `rotates_at` 时，服务会自动生成新 key、持久化到 `jwk_keys`、并热刷新内存 key manager
- 旧 key 会在退役窗口内继续出现在 JWKS，方便已签发 token 平滑过渡

如果数据库里没有可用 key，服务仍然会回退到进程内生成 key，避免本地环境直接起不来；但推荐重新执行 [migrate.sql](/workspace/idp-server/scripts/migrate.sql) 或更新 `jwk_keys`，让服务使用持久化 key。

相关环境变量：

- `SIGNING_KEY_DIR`，默认 `scripts/dev_keys`
- `SIGNING_KEY_BITS`，默认 `2048`
- `SIGNING_KEY_CHECK_INTERVAL`，默认 `1h`
- `SIGNING_KEY_ROTATE_BEFORE`，默认 `24h`
- `SIGNING_KEY_RETIRE_AFTER`，默认 `24h`

关于 `vault://` 和 `kms://`：

- 当前这两种 scheme 已经能接入启动加载流程
- 默认会把引用映射到环境变量读取 PEM
- 例如 `vault://idp/keys/main` 会映射到环境变量 `VAULT_IDP_KEYS_MAIN`
- `kms://prod/signing/key` 会映射到环境变量 `KMS_PROD_SIGNING_KEY`
- 这让本地、容器和简化部署场景可以先跑通，不必先接真正的外部 secret SDK

## Redis Lua 脚本

Lua 脚本放在 [scripts/lua](/workspace/idp-server/scripts/lua)，服务启动时会预热 `SCRIPT LOAD`。

当前已经接入的脚本包括：

- `save_session.lua`
- `delete_session.lua`
- `consume_authorization_code.lua`
- `save_oauth_state.lua`
- `reserve_nonce.lua`
- `increment_with_ttl.lua`
- `revoke_token.lua`
- `rotate_token.lua`

这些脚本目前用于：

- session 与用户索引原子写入/删除
- authorization code 一次性消费
- state / nonce 防重放
- 登录失败计数
- token revoke 黑名单
- refresh token rotation

更多参数约定可以看 [scripts/lua/README.md](/workspace/idp-server/scripts/lua/README.md)。

## 日志与认证中间件

当前 HTTP 层已经接了：

- 请求日志中间件
- Bearer token 认证中间件

日志里会带上这些关键信息：

- `request_id`
- `method`
- `path`
- `status`
- `duration`
- `client_id`
- `subject`

如果请求没有 `X-Request-ID`，服务会自动生成一个，并回写到响应头。

## 当前边界

这版服务已经能做真实的 token 和 userinfo 联调，但还不是完整 OIDC server。

当前边界是：

- `vault://` / `kms://` 目前是环境变量适配层，不是真正的 Vault/KMS SDK 集成
- rotation 现在是进程内定时检查，尚未做独立控制面、审计记录和并发分布式锁
- 联邦登录插件结构已搭好，但外部 OIDC connector 还没接完

## 常用开发命令

```bash
make build
make run
make test
make fmt
make env
make migrate
make migrate-docker
```

## 编译与部署

现在推荐统一走 [Makefile](/workspace/idp-server/Makefile)。

### 本地编译

```bash
make build
```

产物默认在：

```text
bin/idp-server
```

### 本地运行

```bash
make run
```

如果你需要覆盖默认配置，可以直接在命令行传值：

```bash
make run ISSUER=http://localhost:8080 LISTEN_ADDR=:8080
```

### 数据库初始化

本机 MySQL：

```bash
make migrate
```

容器内 MySQL：

```bash
make migrate-docker
```

### Docker 镜像构建

当前默认会使用 [dockerfile.server](/workspace/idp-server/dockerfile.server)：

```bash
make docker-build IMAGE=idp-server:latest
```

### Compose 启停

当前仓库根目录已经有 [docker-compose.yml](/workspace/idp-server/docker-compose.yml)：

```bash
make up
make logs
make down
```

如果 compose 文件不在默认位置，可以传 `COMPOSE_FILE`：

```bash
make up COMPOSE_FILE=../infra/docker-compose.yml
```

### 一个典型部署顺序

开发或测试环境通常就是这几步：

```bash
make migrate-docker
make build
make run ISSUER=http://localhost:8080
```

如果是容器部署，通常就是：

```bash
make migrate-docker
make docker-build IMAGE=idp-server:latest
make up
```
