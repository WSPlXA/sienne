# idp-server 项目详细解说

## 1. 项目定位

这个项目是一个基于 Go 实现的 OAuth2 / OpenID Connect Identity Provider。

它做的事情不是“一个普通登录页面”，而是把下面这些能力收在同一个服务里：

- 用户注册
- 用户登录
- 浏览器会话管理
- OAuth2 授权码流程
- PKCE 校验
- 用户授权同意
- Token 签发
- Refresh Token 轮换
- OIDC `userinfo`
- OIDC Discovery / JWKS
- RP-Initiated Logout（`/connect/logout`）
- 客户端注册与 redirect URI 管理

它的角色是“认证中心 + 授权中心 + Token 发放中心”。

如果外部系统要接入单点登录，这个服务就是那个中心节点。

---

## 2. 这个项目解决什么问题

在一个多应用系统里，通常会有三个痛点：

1. 每个业务系统自己做登录，账号体系分裂。
2. 前端 App、移动端 App、后端服务都需要不同类型的授权方式。
3. 安全边界分散，redirect URI、PKCE、refresh token、logout callback 都容易乱掉。

这个项目的目标，是把这些问题集中到一个 IdP 里处理。

从架构上看，它服务的是三类调用方：

- Web 应用
  典型是浏览器重定向到 `/oauth2/authorize`，走授权码模式。
- 移动端 App
  典型是 public client，使用授权码 + PKCE。
- 后端服务
  典型是 `client_credentials`，不用用户登录，直接拿 access token。

---

## 3. 项目整体分层

目录结构不是装饰，它清楚地表达了职责边界。

### 3.1 `cmd/`

程序入口。

- `cmd/idp/main.go`

只负责：

- 调用 bootstrap 装配整个应用
- 创建 HTTP Server
- 设置超时参数
- 启动监听

这层不承载业务逻辑。

### 3.2 `internal/bootstrap/`

依赖装配中心。

这里把数据库、Redis、仓储、缓存、应用服务、插件注册表、JWT、Router 全接起来。

这一层决定“系统是怎么被拼起来的”。

关键职责：

- 读取环境变量
- 建立 MySQL 连接
- 建立 Redis 连接
- 初始化 repository
- 初始化 cache repository
- 初始化 authn / authz / token / oidc / session / consent / client / register 等 service
- 注册认证插件、grant 插件、client auth 插件
- 初始化 Router

### 3.3 `internal/application/`

这里是真正的业务编排层。

这层不关心 HTTP，不关心数据库 SQL 细节，只关心“业务动作如何完成”。

主要模块：

- `authn`
  认证。处理用户名密码登录、联邦 OIDC 登录、会话创建、登录失败限流。
- `authz`
  授权。校验 client、scope、redirect_uri、PKCE、session、consent。
- `consent`
  授权同意。决定 accept / deny，并写入 consent。
- `client`
  OAuth client 的创建、redirect URI 注册、post logout redirect URI 校验。
- `clientauth`
  token endpoint 上客户端身份认证。
- `register`
  用户注册。
- `session`
  会话注销。
- `token`
  授权码换 token、refresh token 换新 token、client_credentials 发 token。
- `oidc`
  OIDC Discovery、JWKS、userinfo、introspection。
- `keys`
  当前看应用层名里有 `keys`，但真正密钥管理主要落在 infrastructure crypto 里。

### 3.4 `internal/interfaces/http/`

HTTP 接口层。

这层做的事情：

- 解析请求参数
- 调用 application service
- 返回 JSON / HTML
- 设置 cookie
- 组织 redirect

它不应该持有复杂业务状态。

关键 handler：

- `/login`
- `/logout`
- `/connect/logout`
- `/register`
- `/consent`
- `/oauth2/authorize`
- `/oauth2/token`
- `/oauth2/introspect`
- `/oauth2/userinfo`
- `/.well-known/openid-configuration`
- `/oauth2/jwks`

### 3.5 `internal/infrastructure/`

基础设施落地层。

主要包括：

- `storage`
  MySQL / Redis 连接初始化
- `persistence`
  MySQL repository 实现
- `cache/redis`
  Redis cache repository + Lua 脚本预加载
- `crypto`
  JWT、JWK、签名密钥轮换
- `security`
  密码 hash / verify
- `external`
  外部 OIDC Provider 对接

### 3.6 `internal/plugins/`

这是项目里比较关键的扩展点。

它不是过度设计，是真的把“认证方式”和“grant 类型”解耦出来了。

当前有三类插件：

- `authn`
  - password
  - federated_oidc
- `client_auth`
  - client_secret_basic
  - client_secret_post
  - none
- `grant`
  - authorization_code
  - refresh_token
  - client_credentials

这意味着后续要扩展：

- 短信 OTP
- WebAuthn
- SAML Bridge
- private_key_jwt

都有明确插入点，而不是把判断写死在一个巨型 handler 里。

---

## 4. 核心依赖和运行环境

项目当前核心依赖很明确：

- Go 1.26.1
- Gin
- MySQL
- Redis
- JWT/JWK 签名能力

### 4.1 MySQL 的作用

MySQL 承载长期状态：

- 用户
- OAuth Client
- Redirect URI
- Authorization Code
- Consent
- Access Token
- Refresh Token
- Session
- JWK 元数据
- 审计表

### 4.2 Redis 的作用

Redis 承载高频、短 TTL、并发敏感的数据：

- Session Cache
- Token Cache
- OAuth state
- Nonce 防重放
- 登录失败限流
- 部分需要原子性的 token / session 操作

### 4.3 Lua 脚本的作用

`scripts/lua/` 下不是摆设。

这些脚本是为了在 Redis 里做原子操作，避免多次 round-trip 带来的竞态。

例如：

- `save_session.lua`
- `delete_session.lua`
- `consume_authorization_code.lua`
- `rotate_token.lua`
- `revoke_token.lua`
- `increment_with_ttl.lua`

这类逻辑如果拆成多条 Redis 命令，在并发下很容易产生时间窗问题。

---

## 5. 数据模型解说

数据库脚本在 `scripts/migrate.sql`。

它基本定义了整个系统的数据骨架。

### 5.1 `users`

用户主表。

关键字段：

- `user_uuid`
  对外稳定标识，OIDC `sub` 主要就该用它。
- `username`
- `email`
- `password_hash`
- `status`
  `active / locked / disabled / pending_verification`
- `failed_login_count`

### 5.2 `login_sessions`

浏览器会话。

关键字段：

- `session_id`
  cookie 里的值
- `user_id`
- `subject`
- `acr`
- `amr_json`
- `ip_address`
- `user_agent`
- `authenticated_at`
- `expires_at`
- `logged_out_at`

这张表是浏览器登录态的核心。

### 5.3 `oauth_clients`

OAuth client 主表。

关键字段：

- `client_id`
- `client_secret_hash`
- `client_type`
  `public / confidential`
- `token_endpoint_auth_method`
- `require_pkce`
- `require_consent`
- `access_token_ttl_seconds`
- `refresh_token_ttl_seconds`
- `id_token_ttl_seconds`
- `status`

### 5.4 客户端扩展表

- `oauth_client_redirect_uris`
- `oauth_client_post_logout_redirect_uris`
- `oauth_client_grant_types`
- `oauth_client_auth_methods`
- `oauth_client_scopes`

这是典型的一对多配置拆表设计。

优点：

- 查询语义清晰
- 后续扩展 grant / scope 不需要改 schema
- 比把所有东西塞成逗号分隔字符串好太多

### 5.5 `oauth_authorization_codes`

授权码表。

关键字段：

- `code`
- `client_id`
- `user_id`
- `session_id`
- `redirect_uri`
- `scopes_json`
- `state_value`
- `nonce_value`
- `code_challenge`
- `code_challenge_method`
- `expires_at`
- `consumed_at`

它承载授权码模式的短生命周期状态。

### 5.6 `oauth_consents`

用户对 client 的 consent 记录。

关键字段：

- `user_id`
- `client_id`
- `scopes_json`
- `granted_at`
- `revoked_at`

当前设计是“用户 + client 唯一”，scope 作为 JSON 存。

这意味着当前更偏向“最新授权状态覆盖式”而不是“多版本 consent 历史”。

### 5.7 `oauth_access_tokens`

已签发 access token 的落库记录。

关键字段：

- `token_value`
- `token_sha256`
- `client_id`
- `user_id`
- `subject`
- `audience_json`
- `scopes_json`
- `expires_at`
- `revoked_at`

注意：

- 这里同时存 raw token 和 sha256
- 这是为了兼顾查找、吊销和调试

如果以后更强调泄漏面，可以进一步减少 raw token 存储。

### 5.8 `oauth_refresh_tokens`

Refresh Token 记录。

关键字段：

- `token_value`
- `token_sha256`
- `client_id`
- `user_id`
- `subject`
- `revoked_at`
- `replaced_by_token_id`

这个 `replaced_by_token_id` 很关键，它支持 refresh token rotation 链式追踪。

### 5.9 `jwk_keys`

签名密钥元数据。

关键字段：

- `kid`
- `kty`
- `alg`
- `public_jwk_json`
- `private_key_ref`
- `is_active`
- `rotates_at`
- `deactivated_at`

私钥本体不强制存 DB，可通过文件或外部密钥服务引用。

### 5.10 `audit_events`

数据库里有审计表，但从当前 wiring 和 service 代码看，完整审计写入链路还没有真正打通。

这是一个现状判断，不是空谈。

当前更像是“预留了表结构”，不是“已经形成稳定审计子系统”。

---

## 6. 系统启动流程

### 6.1 启动入口

`cmd/idp/main.go` 做三件事：

1. `bootstrap.Wire()`
2. 创建 `http.Server`
3. `ListenAndServe()`

### 6.2 Wire 过程

`internal/bootstrap/wire.go` 是全局总装线。

它的顺序大致是：

1. 读取环境变量
2. 初始化 MySQL
3. 初始化 Redis
4. 初始化 repository / cache repository
5. 初始化密码校验器
6. 初始化 authz / consent / register / client / authn / session / token / oidc service
7. 初始化 federated OIDC provider
8. 初始化 JWT / JWK key manager
9. 初始化 plugin registry
10. 初始化 Auth middleware
11. 初始化 HTTP Router

这条路径决定了所有依赖关系。

如果启动失败，优先看：

- MySQL DSN
- Redis 连接
- signing key 初始化
- federated OIDC 配置

---

## 7. HTTP 路由一览

当前 Router 暴露的主要能力如下：

### 基础能力

- `GET /healthz`
- `GET /.well-known/openid-configuration`
- `GET /oauth2/jwks`

### 用户侧页面与会话

- `GET/POST /login`
- `POST /logout`
- `GET/POST /connect/logout`
- `GET/POST /register`
- `GET/POST /consent`

### OAuth2 / OIDC 主流程

- `GET /oauth2/authorize`
- `POST /oauth2/token`
- `POST /oauth2/introspect`
- `GET /oauth2/userinfo`

### Client 管理

- `POST /oauth2/clients`
- `POST /oauth2/clients/:client_id/redirect-uris`
- `POST /oauth2/clients/:client_id/post-logout-redirect-uris`

---

## 8. 认证流程解说

### 8.1 用户名密码登录

流程：

1. 浏览器访问 `/login`
2. 返回 HTML 或 JSON 登录入口
3. 提交用户名密码
4. `authn.Service` 决定认证方式
5. 若是 password：
   - 检查 IP 限流
   - 检查用户级限流
   - 检查锁定状态
   - 调 password 插件做密码校验
6. 成功后创建 `login_sessions`
7. 将 session 同步写入 Redis cache
8. 发 `idp_session` cookie
9. 重定向回 `return_to`

### 8.2 联邦 OIDC 登录

这个项目支持把“上游 OIDC Provider”接成一个认证方式。

流程大致是：

1. `/login` 页点击 federated OIDC 按钮
2. 认证方式切到 `federated_oidc`
3. 外跳到上游 OIDC Provider
4. 回调回来后拿 `code/state`
5. 插件完成 token / userinfo 交换
6. `authn.Service` 根据 subject / username / email 解析本地用户
7. 创建本地 session
8. 返回原授权流程

这个模式适合：

- 企业统一身份源
- 外部 IAM 联邦
- 把第三方登录收编进本地 IdP

注意一点：

当前本地用户解析是按下面顺序找：

- `subject`
- `username`
- `email`

如果外部 IdP 的 claim 映射没对好，会直接影响联邦登录落本地用户。

---

## 9. 授权流程解说

`authz.Service` 负责 `/oauth2/authorize` 的核心判断。

### 9.1 它会做什么

收到授权请求后，它会依次检查：

1. `response_type` 是否是 `code`
2. `client_id` 是否存在
3. client 是否 active
4. client 是否支持 `authorization_code`
5. `redirect_uri` 是否注册
6. scope 是否都在 client 允许范围内
7. PKCE 是否满足要求
8. session 是否存在、未登出、未过期
9. 如果 client 要求 consent，则检查 consent 是否已存在

### 9.2 它可能返回什么

不是所有情况都直接发 code。

它可能返回三种结果：

- `RequireLogin`
  没登录，要去 `/login`
- `RequireConsent`
  需要授权页确认，要去 `/consent`
- `RedirectURI + Code + State`
  直接签发授权码并回跳 client

### 9.3 PKCE 处理

支持：

- `plain`
- `S256`

如果 client 配置了 `require_pkce`，没有 `code_challenge` 就会被拒绝。

这对 mobile / public client 很重要。

---

## 10. Consent 流程解说

Consent 不是额外页面，而是授权流程的中间关卡。

### 10.1 Prepare

`consent.Service.Prepare()` 做这些事：

1. 解析 `return_to`
2. 确认它必须是本系统的 `/oauth2/authorize`
3. 从 query 里抽出：
   - `client_id`
   - `redirect_uri`
   - `scope`
   - `state`
4. 校验 session
5. 校验 client 与 redirect_uri
6. 校验 scope 是否受允许

### 10.2 Decide

用户提交 accept / deny：

- `accept`
  - 写入或更新 consent
  - 返回原来的 `return_to`
- `deny`
  - 构造带 `error=access_denied` 的 redirect URI

这意味着 consent 页不是独立业务，它严格依附于 authorize 请求上下文。

---

## 11. Token 签发流程解说

`token.Service` 是这个项目最重要的一块之一。

它支持三种 grant：

- `authorization_code`
- `refresh_token`
- `client_credentials`

### 11.1 authorization_code

流程：

1. 校验 client
2. 校验 client secret
3. 消费授权码
4. 校验 code 属于该 client
5. 校验 redirect_uri 一致
6. 校验 PKCE verifier
7. 加载 user
8. 签发 access token
9. 如 scope 包含 `openid`，再签发 ID Token
10. 如 client 支持 refresh token 且 scope 包含 `offline_access`，签发 refresh token
11. token 落 MySQL
12. token 元数据写 Redis cache

### 11.2 refresh_token

流程：

1. 校验 client
2. 校验 refresh token 是否已吊销
3. 查数据库中的 active refresh token
4. 加载 user
5. 签发新 access token
6. 如果 refresh token TTL > 0，则执行 rotation：
   - 旧 refresh token 作废
   - 生成新 refresh token
   - 更新 rotation 链
   - Redis 原子更新

这不是简单“重发 access token”，而是做了 rotation。

### 11.3 client_credentials

流程：

1. 校验 client
2. 校验 client secret
3. 校验请求 scope
4. 签发 access token
5. `sub` 用 client 自己
6. 不生成 user session
7. 不签 refresh token

这适合后端服务调用后端服务。

---

## 12. OIDC 能力解说

`oidc.Service` 提供四块能力：

### 12.1 Discovery

输出标准 OIDC Discovery Document，包含：

- issuer
- authorization endpoint
- token endpoint
- userinfo endpoint
- introspection endpoint
- end session endpoint
- jwks uri
- 支持的 scopes
- 支持的 grant types
- 支持的 client auth method
- 支持的 code challenge method

### 12.2 JWKS

把当前 active public keys 作为 JWK Set 暴露给外部 client / resource server。

### 12.3 userinfo

输入 access token，返回：

- `sub`
- `name`
- `preferred_username`
- `email`
- `email_verified`

### 12.4 introspection

输入 token，检查：

1. token 是否为空
2. token 是否已吊销
3. JWT 是否签名合法、issuer 正确
4. token 是否确实是本服务发出的

然后返回 active / scope / client_id / sub / aud / iss / exp 等。

这让外部资源服务器有两种校验模式：

- 本地验签
- 调 introspection

---

## 13. Logout 流程解说

这里有两个概念，别混。

### 13.1 `/logout`

这是普通本地 session 注销入口。

主要做：

- 校验 CSRF
- 删除 `idp_session`
- 清 Redis session cache
- 标记 DB session logout
- 跳回 `return_to` 或 `/login`

### 13.2 `/connect/logout`

这是 OIDC End Session endpoint。

它服务的是 RP-Initiated Logout。

它接收：

- `client_id`
- `post_logout_redirect_uri`
- `state`

然后做：

1. 校验 post logout redirect URI 是否为该 client 已注册 URI
2. 渲染确认页
3. 提交 POST
4. 注销本地 session
5. 跳转到 `post_logout_redirect_uri`
6. 如果有 `state`，拼回去

这条链是 Web SSO 联动里非常关键的一环。

---

## 14. Client 管理流程解说

项目支持动态创建 client，但不是完全开放式 DCR，而是偏内部管理接口。

### 14.1 创建 client

`POST /oauth2/clients`

创建时会校验：

- `client_id` 格式
- `client_name` 长度
- `client_type`
- `token_endpoint_auth_method`
- grant types 合法性
- scopes 合法性
- redirect URIs 合法性
- post logout redirect URIs 合法性
- public client 必须 PKCE
- public client 不能要求 secret
- confidential client 不能 `auth_method=none`

### 14.2 注册 redirect URI

`POST /oauth2/clients/:client_id/redirect-uris`

### 14.3 注册 post logout redirect URI

`POST /oauth2/clients/:client_id/post-logout-redirect-uris`

这部分用于外部 App 上线前做接入配置。

---

## 15. 如何与别的服务 / App 联动

这是最重要的部分之一。

### 15.1 与 Web 应用联动

典型场景：

- 一个前端 Web App 需要统一登录

它应这样接：

1. 在 IdP 中创建一个 confidential client
2. 注册它的：
   - `redirect_uri`
   - `post_logout_redirect_uri`
3. 浏览器跳转到：
   - `/oauth2/authorize`
4. 用户登录 / consent 完成后回跳到 Web App callback
5. Web App 在后端调用 `/oauth2/token`
6. 拿到：
   - access token
   - id token
   - refresh token（若有）
7. Web App 可调用：
   - `/oauth2/userinfo`
8. 退出登录时跳到：
   - `/connect/logout?...`

Web App 要做的事情：

- 正确保存 OAuth state
- 正确保存 PKCE verifier
- 后端安全地保管 client secret
- 退出登录时使用已注册的 `post_logout_redirect_uri`

### 15.2 与移动端 App 联动

典型场景：

- iOS / Android App 单点登录

推荐方式：

1. 创建 public client
2. `token_endpoint_auth_method = none`
3. `require_pkce = true`
4. 注册自定义 scheme 或 app link 的回调 URI
5. 走 authorization code + PKCE

移动端不要做的事：

- 不要把 confidential secret 硬塞到客户端
- 不要关闭 PKCE

这个项目当前就是按这个方向设计的。

### 15.3 与后端服务联动

典型场景：

- 服务 A 调服务 B，需要 bearer token

做法：

1. 创建 confidential client
2. grant type 只开 `client_credentials`
3. 配置允许 scopes
4. 服务端调用 `/oauth2/token`
5. 传 `grant_type=client_credentials`
6. 拿到 access token
7. 调下游服务时带 bearer token

下游服务可以：

- 本地验 JWT
- 调 `/oauth2/introspect`

### 15.4 与资源服务联动

如果你有单独的 Resource Server，可以这样接：

方式一：本地验 JWT

- 拉取 `/.well-known/openid-configuration`
- 获取 `jwks_uri`
- 拉取 JWKS
- 验签 access token
- 校验：
  - `iss`
  - `aud`
  - `exp`
  - `scp`

方式二：调用 introspection

- 把 access token 发到 `/oauth2/introspect`
- 判断 `active`
- 根据 scope 做授权

如果资源服务数量很多，优先本地验签。

如果资源服务比较薄、实现能力弱，先走 introspection 更稳。

### 15.5 与上游身份源联动

当前支持通过 federated OIDC 接一个上游 OIDC Provider。

适合场景：

- 企业已有统一登录中心
- 你这里想做二级 IdP
- 你要把外部身份映射为本地用户

要配置的环境变量包括：

- `FEDERATED_OIDC_ISSUER`
- `FEDERATED_OIDC_CLIENT_ID`
- `FEDERATED_OIDC_CLIENT_SECRET`
- `FEDERATED_OIDC_REDIRECT_URI`
- claims 映射相关字段

---

## 16. 一条完整的 Web SSO 流程解说

下面用 `web-client` 举例。

### 步骤 1：应用发起授权

浏览器跳到：

`GET /oauth2/authorize?...`

参数典型包括：

- `response_type=code`
- `client_id=web-client`
- `redirect_uri=http://localhost:8081/callback`
- `scope=openid profile email offline_access`
- `state=...`
- `code_challenge=...`
- `code_challenge_method=S256`

### 步骤 2：IdP 检查是否登录

如果没有 `idp_session`，返回：

- `RequireLogin`

浏览器被引到 `/login`

### 步骤 3：用户登录

用户提交用户名密码。

成功后：

- 创建 DB session
- 写 Redis session
- 下发 `idp_session`
- 重定向回原授权路径

### 步骤 4：IdP 检查是否需要 consent

如果 client 配了 `require_consent=true` 且用户没授权过：

- 跳到 `/consent`

### 步骤 5：用户同意

用户点 accept。

系统写入 consent，然后回到 authorize。

### 步骤 6：生成授权码

`authz.Service` 创建一条 `oauth_authorization_codes`。

浏览器被重定向回 client：

`redirect_uri?code=...&state=...`

### 步骤 7：客户端后端换 token

client backend 调 `/oauth2/token`

携带：

- `grant_type=authorization_code`
- `code`
- `redirect_uri`
- `code_verifier`
- client auth

### 步骤 8：IdP 签发 token

服务端返回：

- `access_token`
- `id_token`
- `refresh_token`

### 步骤 9：客户端取用户资料

client 调 `/oauth2/userinfo`

拿到用户信息。

### 步骤 10：退出登录

浏览器访问：

`/connect/logout?...`

服务端注销本地 session，然后跳回：

`post_logout_redirect_uri?state=...`

---

## 17. 当前配置项解说

比较关键的环境变量：

### 基础运行

- `LISTEN_ADDR`
- `ISSUER`
- `APP_ENV`

### MySQL

- `MYSQL_DSN`

或者：

- `MYSQL_HOST`
- `MYSQL_PORT`
- `MYSQL_DATABASE`
- `MYSQL_USER`
- `MYSQL_PASSWORD`

### Redis

- `REDIS_ADDR`

或者：

- `REDIS_HOST`
- `REDIS_PORT`
- `REDIS_PASSWORD`
- `REDIS_DB`
- `REDIS_KEY_PREFIX`

### Session / 登录策略

- `SESSION_TTL`
- `LOGIN_FAILURE_WINDOW`
- `LOGIN_MAX_FAILURES_PER_IP`
- `LOGIN_MAX_FAILURES_PER_USER`
- `LOGIN_USER_LOCK_THRESHOLD`
- `LOGIN_USER_LOCK_TTL`

### JWT / JWK

- `JWT_KEY_ID`
- `SIGNING_KEY_DIR`
- `SIGNING_KEY_BITS`
- `SIGNING_KEY_CHECK_INTERVAL`
- `SIGNING_KEY_ROTATE_BEFORE`
- `SIGNING_KEY_RETIRE_AFTER`

### Federated OIDC

- `FEDERATED_OIDC_ISSUER`
- `FEDERATED_OIDC_CLIENT_ID`
- `FEDERATED_OIDC_CLIENT_SECRET`
- `FEDERATED_OIDC_REDIRECT_URI`
- `FEDERATED_OIDC_CLIENT_AUTH_METHOD`
- `FEDERATED_OIDC_USERNAME_CLAIM`
- `FEDERATED_OIDC_DISPLAY_NAME_CLAIM`
- `FEDERATED_OIDC_EMAIL_CLAIM`
- `FEDERATED_OIDC_SCOPES`
- `FEDERATED_OIDC_STATE_TTL`

---

## 18. 部署与开发运行

### 18.1 本地启动方式

项目已经提供 `docker-compose.yml`。

会起三个服务：

- `db`
- `redis`
- `server`

默认端口：

- MySQL: `3306`
- Redis: `6379`
- IdP: `8080`

### 18.2 初始化数据

`scripts/migrate.sql` 不只是建表，还包含 seed 数据：

- 用户：
  - `alice`
  - `bob`
  - `locked_user`
- client：
  - `web-client`
  - `mobile-public-client`
  - `service-client`

这非常适合本地联调。

### 18.3 默认联调样例

现成能用于联调的典型 client：

- `web-client`
  - Web confidential client
- `mobile-public-client`
  - 移动端 public client
- `service-client`
  - service-to-service client

---

## 19. 现状优点

这个项目目前有几个明显优点。

### 19.1 分层清楚

HTTP、应用编排、仓储、基础设施、插件扩展点是分开的。

### 19.2 核心 OAuth2 / OIDC 闭环已成型

从 authorize 到 token 到 userinfo 到 logout，主链路已经完整。

### 19.3 支持多种 client 形态

- confidential web
- public mobile
- service client

### 19.4 Redis 原子操作设计比较靠谱

对 refresh token rotation、session、nonce、防重放这些热点状态，没偷懒用普通多命令拼装。

### 19.5 密钥轮换有基础设施准备

不是把 JWT 私钥硬写死在代码里。

---

## 20. 当前缺口和后续要做的事情

这部分不能假装没有。

### 20.1 审计链路未真正打通

虽然有 `audit_events` 表，但业务服务里没有形成完整统一的审计事件写入。

建议补：

- 登录成功/失败
- token 签发
- token 刷新
- consent accept/deny
- client 创建
- logout

### 20.2 `id_token_hint` 当前未真正参与 end-session 语义

`/connect/logout` 目前核心还是依赖：

- `client_id`
- `post_logout_redirect_uri`
- `state`

严格 OIDC RP-Initiated Logout 的 `id_token_hint` 校验还有继续完善空间。

### 20.3 资源服务侧权限模型还比较薄

目前 scope 是字符串列表，足够跑通协议，但离精细化授权还差：

- resource indicator
- audience policy
- 细粒度 permission
- tenant / org 维度隔离

### 20.4 用户生命周期还不完整

当前有注册，但缺：

- 邮箱验证流程
- 密码重置
- MFA
- 自助账号管理

### 20.5 运维观测还可以继续补

已有 request log，但还不够：

- metrics
- tracing
- 安全告警
- 审计查询面板

---

## 21. 如果你要把它接进一套真实系统，推荐落地顺序

### 阶段 1：先跑通基础 SSO

先接一个 Web App：

1. 配一个 `web-client`
2. 跑通 authorize -> login -> consent -> token -> userinfo
3. 再跑通 `/connect/logout`

### 阶段 2：补 Resource Server

做一层 API 服务，验证：

- bearer token 验签
- scope 授权
- userinfo 获取

### 阶段 3：接移动端

新建 public client，强制 PKCE。

### 阶段 4：接 service-to-service

开 `client_credentials`，把内部服务调用标准化。

### 阶段 5：补审计、告警、MFA

这时再把安全治理补全。

---

## 22. 这个项目最适合的使用方式

它最适合做：

- 内部业务系统统一登录中心
- 中小型 OAuth2 / OIDC 控制面
- 多端统一认证核心
- 对接上游身份源的二级 IdP

它现在不适合直接宣称自己已经是“大而全企业 IAM 平台”，因为还有这些东西没成熟：

- 完整审计
- 完整账号生命周期
- 多租户隔离
- 组织 / 角色 / 权限模型
- MFA / 风控
- 完整动态客户端注册协议

但作为一个清晰、可继续扩展的 IdP 核心，它已经具备不错的骨架。

---

## 23. 一句话总结

这个项目本质上是一个用 Go 写的、分层比较清楚的 OAuth2 / OIDC 身份中心，已经具备：

- 登录
- 会话
- 授权码
- PKCE
- consent
- token
- userinfo
- introspection
- JWKS
- end-session

这些主干能力。

如果你要把别的 Web、移动端、后端服务接进来，它已经足够当“统一认证入口”；如果你要把它做成完整 IAM 平台，下一步重点应该放在审计、用户生命周期、权限模型和安全增强上。

---

## 24. 本地 App 该怎么拼接授权 URL，什么是 PKCE

### 24.1 本地 App 发起登录时要拼什么 URL

移动端 App 一般走：

- `authorization_code`
- `public client`
- `PKCE`

假设：

- IdP: `http://localhost:8080`
- client_id: `mobile-public-client`
- redirect_uri: `myapp://callback`
- scope: `openid profile offline_access`

那么 App 要把浏览器或系统 WebView 导向：

```text
http://localhost:8080/oauth2/authorize?response_type=code&client_id=mobile-public-client&redirect_uri=myapp%3A%2F%2Fcallback&scope=openid%20profile%20offline_access&state=<random_state>&code_challenge=<pkce_challenge>&code_challenge_method=S256
```

至少要包含：

- `response_type=code`
- `client_id`
- `redirect_uri`
- `scope`
- `state`
- `code_challenge`
- `code_challenge_method`

### 24.2 App 侧完整流程

1. App 本地生成一个高熵随机串，叫 `code_verifier`
2. 用 `SHA256(code_verifier)` 后再做 base64url，得到 `code_challenge`
3. 再生成一个随机 `state`
4. 用上面的参数拼 `authorize` URL
5. 打开系统浏览器
6. 用户登录完成后，IdP 回跳到 `myapp://callback?code=...&state=...`
7. App 校验 `state` 必须和自己发起时一致
8. App 拿到 `code`
9. App 调 `/oauth2/token`
10. 请求体带上：
   - `grant_type=authorization_code`
   - `client_id=mobile-public-client`
   - `code`
   - `redirect_uri=myapp://callback`
   - `code_verifier=<原始 verifier>`
11. IdP 验证 `code_verifier` 是否和之前的 `code_challenge` 对得上
12. 成功后发 token

### 24.3 什么是 PKCE

PKCE 是 Proof Key for Code Exchange。

它解决的是一个非常具体的问题：

- 授权码在浏览器回跳时被别人截走了怎么办

如果没有 PKCE：

- 攻击者拿到 `code`
- 直接去 `/oauth2/token`
- 就可能换到 token

有 PKCE 后：

- 授权阶段只保存 `code_challenge`
- 换 token 阶段必须提交 `code_verifier`
- 攻击者只有 `code`，没有 `verifier`
- 换 token 会失败

所以 PKCE 本质上不是“额外安全参数”，而是“把授权阶段和换 token 阶段绑定成同一个发起方”。

### 24.4 为什么移动端必须用 PKCE

因为移动端通常是 public client：

- 没法安全保存 client secret
- 回调 URL 又容易被系统层面拦截或被调试工具看到

所以 public client 不该依赖 secret，而该依赖 PKCE。

---

## 25. `access_token`、`refresh_token`、`id_token` 分别做什么，introspection 为什么需要

### 25.1 `access_token`

这是“访问资源”的票据。

它的使用场景：

- 调资源服务 API
- 调 `/oauth2/userinfo`
- 让 Resource Server 判断你是否有访问权限

你应该把它理解为：

- 给 API 看
- 不是给前端页面自己解析身份用的

### 25.2 `refresh_token`

这是“续命 access token”的票据。

它的使用场景：

- access token 过期后，不让用户重新登录
- 客户端拿它去 `/oauth2/token` 换一组新的 token

这个项目里 refresh token 还承担 rotation 逻辑：

- 旧 refresh token 一旦使用
- 会被作废
- 发一个新的 refresh token

这样能降低 refresh token 泄漏后的长期风险。

### 25.3 `id_token`

这是“告诉客户端这次登录的是谁”的令牌。

它主要给 OIDC Client 用，不是给资源服务器做 API 授权的。

使用场景：

- Web App 在登录完成后确认当前用户身份
- 读取：
  - `sub`
  - `name`
  - `email`
  - `preferred_username`
  - `nonce`

你应该把它理解为：

- 给 Client 看“用户是谁”
- 不是给 API 看“能不能访问”

### 25.4 三者怎么分工

- `access_token`
  给资源服务器做授权判断
- `refresh_token`
  给客户端续签 token
- `id_token`
  给客户端确认登录身份

把 `id_token` 当 access token 用，是错误的。

### 25.5 introspection 是什么

introspection 是一个服务端查询接口。

客户端或资源服务把 token 发给 IdP：

- `POST /oauth2/introspect`

IdP 返回：

- `active`
- `scope`
- `client_id`
- `sub`
- `aud`
- `iss`
- `exp`

### 25.6 introspection 流程

1. Resource Server 收到 bearer token
2. 不本地验签，或者除了本地验签还想知道它是否已吊销
3. 调用 `/oauth2/introspect`
4. IdP 做：
   - token 是否为空
   - token 是否被吊销
   - JWT 是否有效
   - 是否是本服务签发
5. 返回 `active=true/false`
6. Resource Server 再根据 `scope/aud/sub` 做权限判断

### 25.7 为什么需要 introspection

因为“JWT 能验签成功”不等于“这个 token 现在还能用”。

比如：

- token 已被主动吊销
- token 并不是本服务登记过的
- 资源服务不想自己实现 JWT/JWKS 验证

所以 introspection 的价值在于：

- 在线判断 token 当前是否有效
- 感知吊销状态
- 给薄客户端/薄服务一个更简单的接入方式

---

## 26. JWKS 是什么，怎么用，它和 JWT 是什么关系

### 26.1 JWT 是什么

JWT 是 token 的一种格式。

这个项目发的 access token / id token 默认是 JWT。

JWT 里通常包含：

- Header
  - `alg`
  - `kid`
- Payload
  - `iss`
  - `sub`
  - `aud`
  - `exp`
  - `scp`
  - 其他 claim
- Signature

### 26.2 JWKS 是什么

JWKS 是 JSON Web Key Set。

可以理解为：

- 一组公钥的公开列表

这个项目暴露：

- `GET /oauth2/jwks`

里面会有多个 JWK，每个 key 典型包括：

- `kty`
- `kid`
- `alg`
- `use`
- `n`
- `e`

### 26.3 JWKS 为了什么存在

因为 JWT 是签名过的。

资源服务器要验证签名，就必须拿到公钥。

但公钥不能硬编码在所有下游系统里，否则：

- 换 key 很痛苦
- 轮换麻烦
- 多环境更难维护

所以 IdP 提供 JWKS：

- 下游自己拉
- 根据 JWT header 里的 `kid` 找对应公钥
- 完成验签

### 26.4 JWKS 和 JWT 的关系

关系很简单：

- JWT 是被签出来的 token
- JWKS 是验证这个 token 所需公钥的公开来源

JWT header 里会有：

- `kid`

资源服务拿这个 `kid` 去 JWKS 里找对应 key，再验签。

### 26.5 JWKS 的使用流程

1. 资源服务拿到 access token
2. 先读 Discovery：
   - `/.well-known/openid-configuration`
3. 拿到 `jwks_uri`
4. 拉取 JWKS
5. 解析 JWT header 的 `kid`
6. 在 JWKS 里找到对应公钥
7. 验签
8. 再校验：
   - `iss`
   - `aud`
   - `exp`
   - `scp`

### 26.6 为什么不能只有 JWT 没有 JWKS

如果没有 JWKS：

- 资源服务不知道该用哪个公钥
- 密钥轮换没法做
- 多服务部署时公钥分发会很乱

所以：

- JWT 解决“可携带声明”
- JWKS 解决“可验证签名”

---

## 27. `authn`、`client_auth`、`grant` 分别是什么，为什么这样设计，以及新增 4 种方式该怎么实装

### 27.1 `authn` 是什么

`authn` 是“用户怎么被认证”。

它回答的问题是：

- 这个用户凭什么证明自己是谁

当前实现：

- `password`
- `federated_oidc`

未来扩展：

- 短信 OTP
- WebAuthn
- SAML Bridge

### 27.2 `client_auth` 是什么

`client_auth` 是“客户端怎么证明自己是合法 client”。

它回答的问题是：

- 谁在调用 `/oauth2/token`
- 这个调用方是不是注册过的 client

当前实现：

- `client_secret_basic`
- `client_secret_post`
- `none`

未来扩展：

- `private_key_jwt`

### 27.3 `grant` 是什么

`grant` 是“客户端通过哪种授权方式来拿 token”。

它回答的问题是：

- 凭什么给你发 token

当前实现：

- `authorization_code`
- `refresh_token`
- `client_credentials`

### 27.4 为什么要拆成三层

因为这三个不是一回事。

- `authn`
  是用户身份确认
- `client_auth`
  是客户端身份确认
- `grant`
  是 token 签发依据

举例：

一个移动端 App 登录：

- 用户认证方式可能是 `password` 或 `WebAuthn`
- client 身份方式是 `none`
- grant 是 `authorization_code`

一个后端服务拿 token：

- 没有用户认证
- client_auth 可能是 `client_secret_basic` 或 `private_key_jwt`
- grant 是 `client_credentials`

如果把这三件事揉成一个大 if-else，后面扩展一定烂。

### 27.5 短信 OTP 怎么实装

它属于 `authn` 扩展，不是 grant。

大体流程：

1. 用户输入手机号
2. 服务端生成 OTP code
3. OTP code 写 Redis，短 TTL
4. 调短信网关发短信
5. 用户输入 OTP
6. `authn` 新增 `otp` method
7. 插件校验 OTP 是否存在、是否正确、是否已消费
8. 成功后返回已认证用户
9. 后续 session / authorize / token 流程不变

和 OAuth2 的关系：

- 它只改变“用户怎么登录”
- 不改变 OAuth2 授权码、token、scope 这些协议流

### 27.6 WebAuthn 怎么实装

它也属于 `authn` 扩展。

流程：

1. 用户先注册 passkey / security key
2. 登录时浏览器向服务端请求 challenge
3. 服务端保存 challenge，短 TTL
4. 浏览器调用 WebAuthn API
5. 用户完成设备验证
6. 浏览器把 assertion 发回服务端
7. `authn` 新增 `webauthn` method
8. 插件验证 challenge、credential id、public key 签名
9. 成功后返回已认证用户
10. 后续 session / authorize / token 流程不变

和 OAuth2 的关系同样是：

- 改认证方式
- 不改授权协议主链

### 27.7 SAML Bridge 怎么实装

SAML Bridge 本质上是：

- 把上游 SAML 身份源桥接成当前 IdP 的一种认证方式

它也更适合作为 `authn` method。

流程：

1. 用户点“企业登录”
2. 系统把用户重定向到上游 SAML IdP
3. 上游回传 SAML Response
4. 新增 `saml_bridge` authn method
5. 插件验签 SAML Response
6. 提取 NameID / email / username
7. 映射到本地用户
8. 成功后建立本地 session
9. 后续 authorize / token 完全还是 OAuth2/OIDC

关系上要看清：

- SAML 负责上游认证
- OAuth2/OIDC 负责本系统对下游 App 发 token

也就是：

- 上游是 SAML
- 下游仍然是 OAuth2/OIDC

### 27.8 `private_key_jwt` 怎么实装

它不是 `authn`，也不是 `grant`，而是 `client_auth` 扩展。

适用场景：

- 高安全要求的 confidential client
- 服务端不想用共享 secret

流程：

1. 给 client 预注册公钥或 JWKS
2. client 调 `/oauth2/token` 时，不发 client secret
3. 改为发送一个 client assertion JWT
4. `client_auth` 新增 `private_key_jwt` authenticator
5. 服务端读取 assertion
6. 根据 `iss/sub/aud/jti/exp` 校验 assertion
7. 用预注册公钥验签
8. 通过后认为 client 身份合法
9. 再进入 `authorization_code` 或 `client_credentials` grant 流程

它和 OAuth2 的关系：

- 它是 OAuth2 token endpoint 的一种 client 认证方式
- 不是用户登录方式
- 也不是新的 grant type

### 27.9 这 4 种扩展的归类

- 短信 OTP
  - `authn`
- WebAuthn
  - `authn`
- SAML Bridge
  - `authn`
- `private_key_jwt`
  - `client_auth`

它们和 OAuth2/OIDC 的关系是：

- 改的是“认证输入源”
- 不改“授权码、token、scope、consent、userinfo、logout”这条主链

---

## 28. Nonce、防重放、State、`code_challenge` 分别是什么意思

### 28.1 什么叫 Nonce 防重放

Nonce 可以理解成“一次性随机值”。

防重放的意思是：

- 同一个随机值只能用一次
- 别人把旧请求、旧响应、旧 token 再放一遍，系统也不认

在 OIDC 里，`nonce` 常用于把认证响应和发起方绑定住，避免旧的 ID Token 被重新利用。

这个项目里 Redis 里也专门预留了 nonce/state 相关缓存位和 Lua 脚本。

### 28.2 为什么需要 `state`

`state` 的核心用途有两个：

1. 防 CSRF
2. 把授权响应和原始请求绑定起来

如果没有 `state`：

- 用户浏览器被诱导访问恶意授权链接
- 回调回来时，客户端很难知道这是不是自己刚刚发起的那次登录

所以 client 发起授权时生成一个随机 `state`：

- 先本地保存
- 回调回来后校验完全一致

不一致就直接丢弃。

### 28.3 为什么需要 `code_challenge`

`code_challenge` 是 PKCE 的授权阶段参数。

它的作用是：

- 先把“未来换 token 时必须证明自己知道某个秘密”这件事提前约定好

授权阶段发送：

- `code_challenge`
- `code_challenge_method`

换 token 阶段发送：

- `code_verifier`

服务端做比对。

没有这个机制，授权码被截走就可能被别人换成 token。

### 28.4 `state`、`nonce`、PKCE 分别防什么

- `state`
  防授权响应错绑、防 CSRF
- `nonce`
  防 OIDC 登录响应被重放，尤其是旧 ID Token 被重新利用
- PKCE
  防授权码被截获后被别人去 token endpoint 兑换

这三者都在做“绑定”，但绑定的对象不同：

- `state` 绑定的是“请求和回调”
- `nonce` 绑定的是“认证结果和这次会话”
- PKCE 绑定的是“授权阶段和换 token 阶段”

### 28.5 这三者为什么不能少

如果只做 OAuth2 基础 happy path，不做这三件事，真实环境里会暴露很多洞：

- 回调劫持
- 响应重放
- code interception

所以这不是“协议参数很多很麻烦”，而是每一个参数都在堵一个真实攻击面。

---

## 29. `acr`、`amr_json` 是什么，PKCE 除了 `plain` 和 `S256` 还有什么

### 29.1 `acr` 是什么

`acr` 是 Authentication Context Class Reference。

它表达的是：

- 这次登录是在什么认证等级、什么认证上下文下完成的

你可以把它理解为“认证强度标签”。

当前项目里：

- 密码登录会写成类似 `urn:idp:acr:pwd`
- 联邦 OIDC 会写成类似 `urn:idp:acr:federated_oidc`

它的用途通常有：

- 下游系统判断当前登录强度够不够
- 审计
- 风控
- 为后续 Step-up Authentication 做准备

比如未来如果接 MFA，你可能会有：

- `urn:idp:acr:pwd`
- `urn:idp:acr:pwd_otp`
- `urn:idp:acr:webauthn`

这时资源服务就能区分：

- 只是密码登录
- 还是已做二次认证

### 29.2 `amr_json` 是什么

`amr` 是 Authentication Methods References。

它表达的是：

- 这次登录具体用了哪些认证手段

当前项目把它存成 JSON，是为了支持多值。

例如：

- `["pwd"]`
- `["federated_oidc"]`
- `["pwd","otp"]`
- `["webauthn"]`

和 `acr` 的区别是：

- `acr`
  更偏“认证等级 / 认证上下文”
- `amr`
  更偏“用了哪些认证方法”

举例：

- `acr = urn:idp:acr:pwd_otp`
- `amr = ["pwd","otp"]`

这就很直观。

### 29.3 为什么要存这两个

因为“用户已登录”这句话太粗。

真实系统常常需要知道：

- 是密码登录还是联邦登录
- 是否做了 MFA
- 是否需要 step-up

所以 session 里只存 `user_id` 不够，`acr/amr` 是认证语义的一部分。

### 29.4 PKCE 除了 `plain` 和 `S256` 还有什么

按 OAuth 2.0 PKCE 标准，主流且标准支持的就是：

- `plain`
- `S256`

在实际系统里，应该认为：

- `S256` 是标准推荐做法
- `plain` 只是兼容低能力客户端

一般不应该再自创新的 `code_challenge_method`。

原因很简单：

- 协议互通性会变差
- 各端 SDK 不一定支持
- 安全审计成本上升

所以如果你问“还应该有什么 PKCE 方式”，实际答案是：

- 协议层面通常不该再扩
- 工程上应优先只允许 `S256`

如果系统安全要求高，建议直接：

- public client 强制 `S256`
- 禁用 `plain`

---

## 30. `refresh_token` 应该怎么用，如何携带和请求

### 30.1 `refresh_token` 的作用

它不是给资源服务器的。

它只给授权服务器，也就是这个 IdP 自己看。

它的作用是：

- 当 access token 过期时
- 客户端拿它去换一组新的 token
- 尽量不打断用户会话

### 30.2 什么时候会拿到 `refresh_token`

当前项目里不是所有授权都会发 refresh token。

通常需要同时满足：

- client 支持 `refresh_token` grant
- scope 里包含 `offline_access`
- client 的 refresh token TTL 大于 0

也就是说：

- 有 `offline_access`
  才表示你请求“离线续期能力”

### 30.3 `refresh_token` 应该怎么请求

调用：

- `POST /oauth2/token`

请求示例：

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token&refresh_token=<refresh_token>
```

如果是 public client，没有 `client_secret_basic`，则可能是：

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&client_id=mobile-public-client&refresh_token=<refresh_token>
```

### 30.4 `refresh_token` 是怎么携带的

不是放在 `Authorization: Bearer` 头里。

它一般放在：

- `application/x-www-form-urlencoded` 请求体里

字段名就是：

- `refresh_token`

### 30.5 返回结果是什么

成功后会返回：

- 新的 `access_token`
- 新的 `expires_in`
- 可能还有新的 `refresh_token`

当前项目实现了 rotation，所以通常应该使用返回的新 refresh token 覆盖旧的。

### 30.6 客户端怎么保存 `refresh_token`

按客户端类型不同处理：

- Web confidential client
  - 保存在服务端 session 或服务端数据库
  - 不应该直接裸暴露给浏览器脚本
- Mobile App
  - 保存在系统安全存储里
  - 例如 iOS Keychain / Android Keystore
- Backend service
  - 通常不用 refresh token
  - 更常见是重新走 `client_credentials`

### 30.7 为什么 refresh token 不能乱用

因为它权限比 access token 更危险。

access token 过期短，refresh token 活得久。

如果 refresh token 泄漏：

- 攻击者可以不断换新的 access token

所以它应该：

- 只发给授权服务器
- 安全存储
- 用 rotation
- 能吊销

---

## 31. SAML、身份源、联邦认证三者关系详细解释

### 31.1 什么是身份源

身份源就是“谁说这个用户是谁”。

常见身份源有：

- 本地用户名密码数据库
- 企业 AD / LDAP
- 企业 SAML IdP
- 企业 OIDC IdP
- 社交登录提供方

身份源本质上是认证事实的来源。

### 31.2 本项目不是已经是身份源了吗

是，但这要分层看。

对下游应用来说：

- 这个 IdP 确实是身份源

因为：

- 下游应用信任它签发的 token
- 下游应用把“用户是谁”的结论交给它

但对这个 IdP 自己来说，它的认证来源不一定非得是本地数据库。

它可以再依赖上游身份源。

所以更准确地说：

- 对下游，它是身份源
- 对上游，它也可以是身份代理 / 联邦网关

### 31.3 什么是联邦认证

联邦认证就是：

- 当前系统不直接验证用户口令
- 而是信任另一个身份系统返回的认证结果

例如：

- 本系统把用户重定向到企业 SAML IdP
- 企业 SAML IdP 验证员工身份
- 再把认证结果返回给本系统
- 本系统据此建立自己的 session

这就是联邦认证。

### 31.4 SAML Bridge 是什么

SAML Bridge 是把 SAML 认证结果桥接进当前 IdP。

也就是说：

- 上游：SAML
- 当前 IdP 内部：转换成本地已认证用户
- 下游：继续对外输出 OAuth2 / OIDC

所以它像一个协议桥。

### 31.5 SAML Bridge 的详细流程

1. 用户访问本 IdP 登录页
2. 选择“企业登录”
3. 本 IdP 把用户重定向到上游 SAML IdP
4. 用户在上游登录
5. 上游 SAML IdP 生成带签名的 SAML Response
6. 用户浏览器把 SAML Response 带回本 IdP 的 ACS 端点
7. 本 IdP 校验：
   - XML 签名
   - Issuer
   - Audience
   - 时间窗口
   - InResponseTo
8. 提取用户标识：
   - NameID
   - email
   - username
   - group 等
9. 将上游身份映射为本地用户
10. 创建本地 session
11. 后续继续走本系统的 authorize / consent / token 流程

### 31.6 SAML 和 OAuth2 的关系

它们不是替代关系，而是不同层次。

- SAML 更常见于企业身份联合登录
- OAuth2 / OIDC 更适合下游 App / API 授权和 token 体系

在这个项目里，比较合理的关系是：

- 上游用 SAML 做用户认证
- 本 IdP 做协议转换
- 下游统一只接 OAuth2 / OIDC

这就是“Bridge”的意义。

### 31.7 为什么这样设计有价值

因为下游系统不想同时适配：

- SAML
- OIDC
- 本地密码
- 其他企业协议

把复杂度收在当前 IdP 内部，下游就只信一个 OAuth2/OIDC 出口。

---

## 32. `id_token` 和 `offline_access` 的关系

### 32.1 它们不是一个维度的东西

- `id_token`
  是一个令牌类型
- `offline_access`
  是一个 scope

它们不是一一对应关系。

### 32.2 `id_token` 是什么时候发的

当前项目里，只要 scope 里有：

- `openid`

并且走的是 OIDC 登录流程，系统就会发 `id_token`。

### 32.3 `offline_access` 是什么时候起作用

`offline_access` 表示客户端希望：

- 用户不在线时
- 也能继续刷新 token

它通常用来触发 refresh token 的发放。

### 32.4 两者的关系

常见组合是：

- `openid profile email offline_access`

这样就可能同时得到：

- `id_token`
- `access_token`
- `refresh_token`

其中：

- `id_token`
  说明“这次登录的是谁”
- `offline_access`
  说明“我还想拿 refresh token”

所以它们关系是：

- 经常一起出现
- 但语义完全不同

### 32.5 为什么有的系统有 `id_token` 却没有 refresh token

因为：

- 只请求了 `openid`
- 没请求 `offline_access`

这很正常。

### 32.6 为什么有 refresh token 但重点不在 `id_token`

比如某些长会话 App 更关心：

- 用户不用频繁登录

那它更在意 refresh token。

而 `id_token` 更多用于首次登录确认和会话建立。

---

## 33. 用户在 IdP 认证完成后，后续请求资源应该怎么做

这个问题必须分客户端类型讲，不然一定混。

### 33.1 共同原则

用户在 IdP 认证完成，不等于资源服务器自动知道他是谁。

真正传递到资源服务器的，是：

- `access_token`

所以后续请求 API 的最常见方式是：

```http
Authorization: Bearer <access_token>
```

然后资源服务器自己决定怎么校验这个 token。

常见有两种：

- 本地验 JWT + JWKS
- 调 introspection

### 33.2 Web confidential client 的后续请求流程

典型结构：

- Browser
- Web Frontend
- Web Backend
- Resource API

#### 方式 A：后端代理 API 调用

这是最常见也最稳的方式。

流程：

1. 用户在浏览器完成 IdP 登录
2. Web Backend 通过 `/oauth2/token` 换到 token
3. Web Backend 把 token 保存在自己服务端 session 或数据库
4. 浏览器后续访问 Web Backend
5. Web Backend 代表用户调用下游 API
6. Web Backend 在请求头带：
   - `Authorization: Bearer <access_token>`
7. Resource API 校验 token

优点：

- access token 不直接暴露给浏览器 JS
- 安全边界更清楚

#### 方式 B：前端直接调 API

也可以，但风险更高。

流程：

1. 前端拿到 access token
2. 前端直接请求 API
3. 带 bearer token

问题是：

- token 更容易暴露给浏览器脚本
- XSS 风险直接变成 token 泄漏风险

所以对 confidential web app，优先推荐服务端持有 token。

### 33.3 Mobile public client 的后续请求流程

移动端一般没有自己的安全后端来代持 token，所以常见是：

1. App 完成授权码 + PKCE
2. `/oauth2/token` 拿到 access token
3. App 安全保存：
   - access token
   - refresh token
4. 调 API 时带：
   - `Authorization: Bearer <access_token>`
5. API 校验 token
6. access token 过期时，App 用 refresh token 去换新 token

移动端重点是：

- access token 放内存或短期缓存
- refresh token 放安全存储
- 绝不伪装成 confidential client

### 33.4 SPA / 前端单页应用的后续请求流程

如果未来你要做 SPA，最好仍然走：

- authorization code + PKCE

后续请求 API 时：

1. SPA 持有 access token
2. 调 API 时带 bearer token
3. API 自己验签或调 introspection

但 SPA 比传统 Web 后端代理模式更脆弱，因为 token 落在浏览器环境。

所以要额外重视：

- XSS
- token 生命周期
- refresh token 存储方式

### 33.5 Backend service 的后续请求流程

服务端调用服务端，不涉及用户浏览器会话。

流程：

1. 服务 A 用 `client_credentials` 拿 access token
2. 服务 A 调服务 B
3. 带 bearer token
4. 服务 B 校验 token

此时 token 表示的主体通常不是用户，而是 client 自己。

也就是说：

- `sub = client_id`

这种模式适合机器身份。

### 33.6 Resource API 收到 bearer token 后应该做什么

不管调用方是谁，API 收到：

```http
Authorization: Bearer <access_token>
```

后至少应该做：

1. 验签或 introspection
2. 校验 `iss`
3. 校验 `exp`
4. 校验 `aud`
5. 校验 `scope`

如果是用户 token，再取：

- `sub`

再做业务级授权。

### 33.7 资源服务器的两种实现方式

#### 方式一：本地验 JWT

适合：

- 高吞吐 API
- 服务数量多
- 低延迟要求高

流程：

1. 通过 JWKS 验签
2. 看 claim
3. 本地判断 scope 和 audience

优点：

- 快
- 不依赖每次回源 IdP

缺点：

- 想感知吊销更复杂

#### 方式二：调用 introspection

适合：

- 低吞吐内部服务
- 安全要求更高
- 想实时感知吊销状态

流程：

1. 收到 token
2. 调 `/oauth2/introspect`
3. 读 `active`
4. 再做业务授权

优点：

- 能实时知道 token 是否已失效/吊销

缺点：

- 每次请求都多一次网络调用
- 吞吐压力会集中到 IdP

### 33.8 一句话说清后续资源访问

用户在 IdP 登录完成后，真正访问资源时不是“继续带 session 去打 API”，而是：

- 客户端先拿到 `access_token`
- 请求资源时带 `Bearer access_token`
- 资源服务器再根据 JWT/JWKS 或 introspection 判断是否放行

---

## 34. `client_credentials` 是什么

### 34.1 它是什么

`client_credentials` 是 OAuth2 的一种 grant type。

它解决的问题不是“用户登录”，而是：

- 一个服务怎么以自己的身份拿 token

也就是说，它面向的是机器身份，不是人。

### 34.2 它和授权码模式的区别

授权码模式里，核心主体通常是：

- 用户

而 `client_credentials` 里，核心主体是：

- client 自己

所以：

- 没有登录页面
- 没有 consent
- 没有浏览器回跳
- 没有 session cookie

### 34.3 典型使用场景

适合：

- 后端服务 A 调后端服务 B
- 定时任务调用内部 API
- 网关调用下游服务
- 机器对机器的受控访问

不适合：

- 浏览器用户登录
- 移动端用户授权
- 任何需要“知道当前是谁登录”的场景

### 34.4 这个项目里它怎么工作

当前项目支持：

- `grant_type=client_credentials`

处理流程大致是：

1. client 调 `/oauth2/token`
2. 携带自己的 client 身份凭证
   - 当前通常是 `client_secret_basic` 或 `client_secret_post`
3. 指定：
   - `grant_type=client_credentials`
4. IdP 校验：
   - client 是否存在
   - client 是否 active
   - client 是否允许 `client_credentials`
   - client secret 是否正确
   - 请求 scope 是否在允许范围内
5. 成功后签发 access token

这个 token 的特点是：

- 没有用户 session
- `sub` 通常是 `client_id`
- 不会发 `id_token`
- 一般也不会发 `refresh_token`

### 34.5 请求示例

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(service-client:service-secret)

grant_type=client_credentials&scope=internal.api.read
```

返回：

- `access_token`
- `token_type`
- `expires_in`
- `scope`

### 34.6 下游服务怎么看这种 token

下游资源服务拿到后，不应把它当作“用户 token”。

它代表的是：

- 某个已注册 client 的机器身份

所以业务判断时要区分：

- 这是用户身份 token
- 还是服务身份 token

如果是 `client_credentials` token，常见做法是：

- `sub = client_id`
- `cid = client_id`
- 根据 scope 决定能访问哪些内部 API

### 34.7 为什么需要它

因为并不是所有 API 调用都来自用户浏览器。

真实系统里，大量请求来自：

- worker
- cron
- API gateway
- backend job
- 内部服务编排

这些场景如果硬套用户登录模型，会很蠢，也不稳定。

所以 `client_credentials` 的意义就是：

- 给机器一个规范的、可审计的、可授权的身份通道

---

## 35. MFA 应该怎么做

### 35.1 MFA 是什么

MFA 是 Multi-Factor Authentication，多因素认证。

意思是：

- 不是只靠一个因子证明身份
- 而是至少两个不同类型的因子联合认证

常见因子类型：

- 知识因子
  - 密码
- 持有因子
  - 手机短信 OTP
  - TOTP App
  - 硬件 Key
- 生物因子
  - 指纹
  - 面容

### 35.2 为什么需要 MFA

因为只靠密码太脆弱。

密码会遇到：

- 撞库
- 钓鱼
- 弱密码
- 重复使用

加上 MFA 之后，即使密码泄漏，攻击者通常还差第二个因子。

### 35.3 MFA 在这个项目里应该挂在哪

MFA 主要属于：

- `authn`

因为它解决的是：

- 用户怎么完成身份确认

而不是：

- grant type
- client auth

### 35.4 最基本的 MFA 设计方式

比较务实的做法是两阶段：

#### 阶段 1：主认证

先完成第一因子认证，例如：

- 密码
- federated OIDC
- WebAuthn

#### 阶段 2：附加认证

如果策略要求 MFA，再做第二因子：

- OTP
- TOTP
- WebAuthn touch

只有第二因子也通过后，才算最终认证完成。

### 35.5 在当前架构下怎么落地

比较合理的方式不是在一个 handler 里疯狂 if-else，而是这样拆：

#### 方案 A：把 MFA 作为新的 `authn` method 组合

例如：

- `password`
- `password_otp`
- `password_webauthn`

优点：

- 简单直接

缺点：

- method 组合会爆炸

#### 方案 B：把 MFA 作为 authn service 的二阶段状态机

更推荐。

流程可以是：

1. 用户提交用户名密码
2. 第一因子通过
3. `authn.Service` 不立即创建正式 session
4. 先创建一个短 TTL 的“待完成 MFA 上下文”
   - 放 Redis
   - 记录 user id、method、expires_at、nonce
5. 返回：
   - `mfa_required=true`
   - `mfa_token=<短期上下文 token>`
6. 前端跳到 MFA 页面
7. 用户输入 OTP / 完成 WebAuthn
8. 服务端带着 `mfa_token` 校验第二因子
9. 通过后才创建正式 `login_session`
10. 设置：
   - `acr`
   - `amr_json`

这条路更干净。

### 35.6 用短信 OTP 做 MFA 的流程

1. 用户密码登录成功
2. 系统判断该账号需要 MFA
3. 生成 OTP code
4. OTP 写 Redis，TTL 短，例如 3 分钟
5. 调短信服务发送验证码
6. 前端进入 OTP 输入页
7. 用户提交 OTP + `mfa_token`
8. 服务端校验：
   - `mfa_token` 是否有效
   - OTP 是否匹配
   - OTP 是否已使用
9. 通过后创建正式 session
10. 设置：
   - `acr = urn:idp:acr:pwd_otp`
   - `amr_json = ["pwd","otp"]`

### 35.7 用 TOTP 做 MFA 的流程

如果你不想依赖短信，TOTP 更常见也更稳。

流程：

1. 用户先绑定 TOTP secret
2. 登录时密码通过
3. 系统要求输入 6 位动态码
4. 服务端用同一个 secret 验证时间窗口内 OTP
5. 验证通过后创建 session

优点：

- 不依赖短信网关
- 成本更低
- 抗短信链路问题更好

### 35.8 用 WebAuthn 做 MFA 的流程

也可以把 WebAuthn 作为第二因子。

流程：

1. 第一因子通过
2. 服务端下发 challenge
3. 浏览器调用 WebAuthn API
4. 用户完成设备侧确认
5. 服务端验签 assertion
6. 通过后创建 session

这个模式可以得到非常强的认证强度。

### 35.9 MFA 和 `acr` / `amr_json` 的关系

MFA 落地后，`acr` 和 `amr_json` 就变得非常有意义。

例如：

- 仅密码登录
  - `acr = urn:idp:acr:pwd`
  - `amr = ["pwd"]`
- 密码 + OTP
  - `acr = urn:idp:acr:pwd_otp`
  - `amr = ["pwd","otp"]`
- WebAuthn
  - `acr = urn:idp:acr:webauthn`
  - `amr = ["webauthn"]`

资源服务或高敏页面就可以要求：

- 只有 `acr` 达到某等级才允许访问

### 35.10 MFA 和 OAuth2/OIDC 的关系

MFA 不会改变：

- 授权码流程
- token endpoint
- refresh token
- JWKS

它改变的是“用户能否被视为已认证”以及“认证强度”。

所以它属于认证前置环节，而不是 OAuth2 grant 本身。

### 35.11 这个项目如果要实装 MFA，推荐落地顺序

建议顺序：

1. 先实现 TOTP
   - 不依赖第三方短信服务
   - 便于本地调试
2. 再做短信 OTP
   - 需要短信网关
   - 成本和风控更复杂
3. 最后做 WebAuthn
   - 交互和设备兼容更复杂

### 35.12 要新增哪些存储

如果做 MFA，至少要新增这些数据：

- 用户 MFA 配置表
  - 是否启用 MFA
  - MFA 类型
  - TOTP secret / WebAuthn credential metadata / 手机号等
- MFA challenge / pending auth 状态缓存
  - Redis
  - 短 TTL
- 审计事件
  - MFA challenge issued
  - MFA success
  - MFA failure

### 35.13 一句话总结 MFA

MFA 不是再加一个页面那么简单，它应该是：

- 认证状态机的一部分
- session 创建前的第二道关
- 并且最终要反映到 `acr` 和 `amr_json`

---

## 36. 二维码登录怎么登录

### 36.1 二维码登录本质上是什么

二维码登录不是新的 OAuth2 grant，也不是新的 token 类型。

它本质上是：

- 用“已登录设备”去确认“另一台未登录设备”的登录请求

你可以把它理解成一种特殊的 `authn` 方式，或者更准确一点：

- 一种跨设备认证确认流程

常见场景：

- PC 网页没登录
- 手机 App 已经登录
- PC 展示二维码
- 手机扫码确认
- PC 自动变成已登录状态

### 36.2 它和 OAuth2 / OIDC 的关系

二维码登录通常不替代 OAuth2 / OIDC，而是给“登录这一步”换了一种入口。

关系应该这样看：

- 二维码登录负责“确认用户身份”
- OAuth2 / OIDC 继续负责“后续授权码、token、session、userinfo”

也就是说：

- 扫码成功后，本系统仍然应该建立正式 session
- 如果扫码登录发生在 `/oauth2/authorize` 上下文里，后续仍然可以继续走 authorize -> consent -> code -> token

所以它更接近：

- `authn` 的一种实现形态

而不是：

- `grant`

### 36.3 最常见的二维码登录结构

它至少涉及两个终端：

- 被登录端
  - 通常是 PC 浏览器
- 扫码确认端
  - 通常是已登录手机 App

还要有服务端短期状态：

- 二维码会话 / login challenge

### 36.4 推荐的服务端状态设计

建议新增一个短 TTL 的二维码登录上下文，放 Redis。

大概字段：

- `qr_login_id`
- `status`
  - `pending`
  - `scanned`
  - `approved`
  - `rejected`
  - `expired`
- `return_to`
  - 如果是在 OAuth 授权流中发起，需要把原始授权路径挂回去
- `client_id`
  - 可选
- `redirect_uri`
  - 可选
- `scope`
  - 可选
- `state`
  - 可选
- `requested_at`
- `expires_at`
- `approved_by_user_id`
- `approved_session_id`

这个状态不该落 MySQL 主库长期保存，短期放 Redis 更合理。

因为它是：

- 高频
- 短生命周期
- 强状态机

### 36.5 二维码里应该放什么

二维码里不要直接放用户信息，也不要放 access token。

二维码里更合理的是一个短期 URL，例如：

```text
http://localhost:8080/login/qr/scan?qr_login_id=<opaque_id>&nonce=<opaque_nonce>
```

更进一步，建议不要让 `qr_login_id` 可猜。

应该使用：

- 高熵随机值
- 短 TTL
- 一次性使用

### 36.6 被登录端（PC）流程

1. PC 打开登录页
2. 选择“二维码登录”
3. 服务端创建一个 `qr_login_id`
4. Redis 写入 `pending` 状态
5. 页面展示二维码
6. PC 页面轮询，或者使用 SSE / WebSocket 订阅状态
7. 等待手机扫码结果
8. 一旦状态变成 `approved`
9. 服务端给 PC 建立正式 `idp_session`
10. 若有 `return_to`，继续回到授权流程

### 36.7 手机端流程

1. 手机 App 已登录
2. 用户打开扫一扫
3. 扫到二维码 URL
4. App 调服务端查询这个二维码登录请求
5. 服务端返回本次登录请求摘要
   - 登录地点
   - 浏览器信息
   - 时间
   - 请求应用
6. 用户确认或拒绝
7. App 把确认结果发给服务端
8. 服务端将 `qr_login_id` 状态改为：
   - `approved`
   - 并记录 `approved_by_user_id`
9. PC 端感知状态变化
10. PC 端完成登录

### 36.8 最关键的一步：PC 怎么“变成已登录”

这是二维码登录里最核心的点。

手机端确认成功后，不能直接把手机 access token 拿去给 PC 用。

正确方式是：

- 手机端只是“批准”
- 服务端据此给 PC 创建一条新的浏览器 session

也就是说：

- 手机和 PC 是两个不同会话
- 不能共享同一个 session id
- 不能把手机 token 直接塞给 PC

更合理的流程是：

1. 手机端确认
2. 服务端把二维码状态置为 `approved`
3. PC 下一次轮询命中 `approved`
4. PC 对这个 `qr_login_id` 发起最终兑换
5. 服务端验证：
   - 状态确实是 `approved`
   - 没过期
   - 没消费过
6. 服务端为 PC 创建新的 `login_session`
7. 服务端回写浏览器 cookie

### 36.9 如果二维码登录发生在 OAuth 授权流中

这才是和当前项目结合最紧的场景。

例如：

1. 浏览器先访问 `/oauth2/authorize`
2. 因为没登录，被跳到 `/login?return_to=...`
3. 用户选择二维码登录
4. 服务端生成二维码登录上下文时，把 `return_to` 也带进去
5. 扫码批准成功后
6. 服务端给 PC 建立 session
7. 再重定向回原来的 `/oauth2/authorize?...`
8. 后面该 consent 就 consent，该发 code 就发 code

这样二维码登录只是替换了“用户如何完成登录”，不会破坏 OAuth2/OIDC 主链。

### 36.10 二维码登录需要哪些接口

比较务实的一组接口可以是：

- `POST /login/qr`
  - 创建二维码登录请求
  - 返回二维码内容、过期时间
- `GET /login/qr/:id`
  - 给 PC 端轮询状态
- `POST /login/qr/:id/approve`
  - 已登录手机端批准登录
- `POST /login/qr/:id/reject`
  - 已登录手机端拒绝登录
- `POST /login/qr/:id/consume`
  - PC 端消费批准结果，换成正式 session

这里的重点是：

- `approve`
  不是直接登录
- `consume`
  才是把批准结果兑换成 PC session

### 36.11 为什么需要 `consume` 这一步

因为否则状态机会很乱。

如果手机一批准，服务端立刻“替 PC 登录”，你会碰到这些问题：

- PC 页已经关闭怎么办
- 多个标签页同时轮询怎么办
- 批准结果被重放怎么办
- 扫码批准和浏览器会话绑定不上怎么办

所以更稳的模型是：

- 手机批准
- PC 消费

这和授权码的思路其实很像：

- 一方生成短期状态
- 另一方完成兑换

### 36.12 二维码登录如何防攻击

二维码登录的攻击面不少，至少要做这些：

#### 1. 二维码短 TTL

例如：

- 1 分钟
- 2 分钟

过期自动失效。

#### 2. 一次性消费

一个 `qr_login_id` 成功消费后必须立刻失效。

#### 3. 手机端必须已登录

扫码批准的前提是：

- 手机端已经有有效 session

不然二维码登录就退化成公开入口。

#### 4. 手机端要展示确认信息

至少给用户看：

- 哪台设备
- 哪个浏览器
- 哪个应用
- 什么时间发起

不然用户很容易被钓鱼扫码。

#### 5. PC 最终兑换时要绑定浏览器上下文

比如保存：

- 轮询 token
- csrf-like challenge
- device nonce

确保不是其他人拿到了 `qr_login_id` 就能消费。

#### 6. 审计

建议记录：

- 二维码创建
- 扫码
- 批准
- 拒绝
- 消费成功
- 消费失败

### 36.13 二维码登录和 MFA 的关系

二维码登录本身不一定是 MFA。

它可能只是：

- 一种替代密码输入的登录方式

但它也可以升级成 MFA：

- PC 输入密码
- 再要求手机扫码确认

那这时二维码就成了第二因子。

所以：

- 作为独立登录方式，它属于 `authn`
- 作为第二因子，它也可以挂在 MFA 状态机里

### 36.14 当前项目如果要实装二维码登录，最推荐的挂载方式

建议这样做：

1. 在 `/login` 页新增二维码登录入口
2. 在 Redis 增加 `qr_login` 短期状态
3. 在 `authn` 体系里增加一个“扫码确认完成后创建 session”的流程
4. 如果存在 `return_to`，登录成功后继续回原授权流程

不要做成：

- 手机 token 直接复制给 PC
- 浏览器和手机共享一个 session id
- 二维码长期有效

这些都属于差品味设计。

### 36.15 一句话总结二维码登录

二维码登录不是“扫码后把手机登录态搬到 PC”，而是：

- 用已登录手机批准一次新的浏览器登录请求
- 然后由服务端为浏览器创建一个新的正式 session

---

## 37. WebAuthn (Passkey) 详细实现方案

本项目基于 WebAuthn (Passkey) 标准实现了无密码认证和多因子认证 (MFA) 结合的方案。

### 37.1 核心组件与分层

WebAuthn 的实现遵循了项目的分层架构：

1.  **基础设施层 (`internal/infrastructure/security/passkey.go`)**
    - 使用 `github.com/go-webauthn/webauthn` 库作为核心引擎。
    - 实现了 `internal/ports/security/passkey.go` 中定义的 `PasskeyProvider` 接口。
    - 负责 RP (Relying Party) 配置、凭据验证 (Attestation/Assertion) 以及本地用户模型与库模型的适配。

2.  **应用层 - 注册服务 (`internal/application/passkey/service.go`)**
    - 处理用户的 Passkey 绑定流程。
    - `BeginSetup`: 生成 WebAuthn 注册选项 (options)，并将 challenge 存入 MFA Cache (Redis)。
    - `FinishSetup`: 验证浏览器返回的凭据，并调用 Repository 持久化。

3.  **应用层 - 认证服务 (`internal/application/authn/service.go`)**
    - 在 `Authenticate` 流程中，如果用户开启了 MFA 且注册了 Passkey，则触发 MFA 状态机。
    - `BeginMFAPasskey`: 生成 WebAuthn 登录选项。
    - `VerifyMFAPasskey`: 验证签名，成功后创建正式 Session。

4.  **持久层 (`internal/persistence/passkey_credential_repo_sql.go`)**
    - 负责 `user_webauthn_credentials` 表的读写。

### 37.2 数据模型

存储在 `user_webauthn_credentials` 表中：

- `id`: 自增主键。
- `user_id`: 关联用户。
- `credential_id`: WebAuthn 凭据 ID (唯一)。
- `public_key`: 凭据公钥 (通常包含在 `credential_json` 中)。
- `credential_json`: **关键字段**。存储了 `go-webauthn` 的完整凭据记录对象，包含算法、AAGUID、签名计数等。
- `last_used_at`: 记录最近一次认证成功的时间。

### 37.3 交互逻辑：两阶段提交

无论是注册还是登录，都采用了经典的 `Begin` / `Finish` 两阶段逻辑：

- **阶段一 (Begin)**:
  - 客户端请求 Challenge。
  - 服务端生成 Challenge、RP ID、允许的凭据列表等。
  - 服务端将上下文 (Session) 序列化存入 Redis，TTL 通常为 1-5 分钟。
- **阶段二 (Finish)**:
  - 浏览器通过 `navigator.credentials` 获取结果后发回服务端。
  - 服务端从 Redis 取回上下文。
  - 服务端调用 `go-webauthn` 校验签名、Challenge 一致性、签名计数防克隆。
  - 成功后完成后续业务 (保存凭据或创建 Session)。

### 37.4 集成 MFA 状态机

Passkey 在本项目中不仅可以作为独立认证，更多地是作为 MFA 的第二因子：

1.  用户输入密码登录。
2.  `authn.Service` 检查用户是否需要 MFA。
3.  如果用户有 Passkey，Service 会在 Redis 中创建一个 `PendingMFA` 状态，模式为 `MFAModePasskeyTOTPFallback`。
4.  浏览器被引导至 `/login/totp` 页面，展示 WebAuthn 触发按钮。
5.  用户点击后触发 Passkey 校验，校验通过即视为 MFA 完成。

### 37.5 为什么选择 `go-webauthn` 库

- **合规性**: 完整支持 FIDO2 / WebAuthn L1/L2 规范。
- **无状态友好**: 凭据对象可以直接序列化为 JSON 存入数据库，验证时只需重新反序列化，非常适合分布式架构。
- **多平台支持**: 自动处理 iOS/Android/Windows Hello 等不同平台的签名细节。

### 37.6 安全增强点

- **RP ID 绑定**: 严格校验 RP ID，防止跨域劫持。
- **Challenge 随机性**: 每次请求生成高熵随机 Challenge，且在 Redis 中一次性消费。
- **签名计数校验**: 每次登录后更新数据库中的计数，如果发现新提交的计数小于旧计数，判定为凭据被克隆，立即拦截。

---

## 38. 高性能状态机与原子 CAS (High-Performance State Machine & Atomic CAS)

为了应对超大规模并发场景下的性能瓶颈与数据一致性挑战，项目对会话（Session）与 MFA 挑战（Challenge）的状态管理进行了深度重构。

### 38.1 核心设计：位掩码 (Bitmask)

传统的“字符串状态”（如 `status="active"`）在进行逻辑判断时涉及内存分配、编码转换和多轮 CPU 周期。本项目引入了基于 `uint32` 的位掩码设计：

- **硬件亲和性**：状态检查从字符串匹配简化为单条 CPU 指令 `mask & StateActive != 0`。位运算是 CPU 的原生指令，通常只需 1 个时钟周期，极大地提升了处理速度。
- **内存优化**：使用 4 字节的整数替代变长字符串，显著降低了内存占用和缓存行（Cache Line）压力，减轻了 Golang 运行时的 GC 负担。
- **逻辑表达力**：通过位运算（AND/OR/NOT）可以一次性判定多个复杂业务条件的组合（如“活跃且未锁定且已完成 MFA”），代码更加简洁且不易出错。

### 38.2 乐观锁：原子 CAS (Compare-And-Swap)

在分布式环境下，多个实例同时修改同一个会话状态可能导致“丢失更新”。本项目在存储层实现了基于版本号的乐观锁：

1. **版本化状态**：每个记录包含一个 `state_ver`（状态版本号）。
2. **读-改-写 原子化**：通过 Redis Lua 脚本，在写入前校验当前版本号是否与读取时一致。
3. **CAS 冲突处理**：如果版本不匹配（说明期间有其他实例修改了数据），Lua 脚本返回错误代码，应用层捕捉到 `ErrStateVersionConflict` 后可选择重试或向用户报错。

### 38.3 存储优化：Packed State 与 HMGet

为了进一步压榨性能，项目在 Redis 交互层进行了专项优化：

- **定点读取 (HMGet)**：放弃了返回全量 Map 的 `HGetAll`，改用 `HMGet` 定点读取特定字段。这避免了哈希表的动态扩容、Map 的分配以及频繁的反序列化开销。
- **状态压缩 (BITFIELD)**：部分热点数据（如 Session 状态位与版本号）通过 Redis `BITFIELD` 命令打包存储在独立的键中。仅需 8 字节（32位状态 + 32位版本）即可表达完整的并发控制元数据。

### 38.4 架构收益：高性能与高可靠并重

- **一致性保证**：彻底解决了并发登录、并发 MFA 确认等场景下的数据竞争问题。
- **Fail-Closed 安全设计**：位掩码的转换逻辑内置了“冲突即拒绝”的防御策略，防止非法状态跃迁。
- **吞吐量提升**：显著降低了 Redis 的网络包大小和应用服务器的 CPU 消耗，系统 P99 延迟更加平滑。

