# idp-server Sequence 图

基于 [detail.md](/F:/source%20code/palyground/workspace/idp-server/detail.md) 中现有流程整理。

## 1. Web Client 向 idp-server 请求

```mermaid
sequenceDiagram
    autonumber
    participant Browser as Web Client(Browser)
    participant WebBackend as Web Client Backend
    participant IdP as idp-server
    participant Redis as Redis
    participant MySQL as MySQL

    Browser->>WebBackend: 访问受保护页面
    WebBackend-->>Browser: 302 跳转到 /oauth2/authorize
    Browser->>IdP: GET /oauth2/authorize?client_id=web-client&scope=openid...
    IdP->>Redis: 查 session cache
    IdP-->>Browser: 未登录，302 跳转 /login?return_to=...

    Browser->>IdP: POST /login(username, password)
    IdP->>MySQL: 校验用户/写 login_sessions
    IdP->>Redis: 写 session cache
    IdP-->>Browser: Set-Cookie(idp_session) + 302 回原 /oauth2/authorize

    Browser->>IdP: 再次 GET /oauth2/authorize
    IdP->>Redis: 读 session
    IdP->>MySQL: 校验 client / redirect_uri / consent / 写 authorization_code
    IdP-->>Browser: 302 回 Web Client callback?code=...&state=...

    Browser->>WebBackend: GET /callback?code=...&state=...
    WebBackend->>IdP: POST /oauth2/token(grant_type=authorization_code)
    IdP->>MySQL: 消费授权码，签发并落库 token
    IdP->>Redis: 写 token cache
    IdP-->>WebBackend: access_token / id_token / refresh_token
    WebBackend-->>Browser: 建立应用侧登录态
```

## 2. Mobile Client 向 idp-server 请求

```mermaid
sequenceDiagram
    autonumber
    participant App as Mobile Client(App)
    participant Browser as System Browser
    participant IdP as idp-server
    participant Redis as Redis
    participant MySQL as MySQL

    App->>App: 生成 PKCE(code_verifier/code_challenge) 与 state
    App->>Browser: 打开 /oauth2/authorize?client_id=mobile-client&code_challenge=S256...
    Browser->>IdP: GET /oauth2/authorize
    IdP->>Redis: 查 session cache
    IdP-->>Browser: 未登录，302 跳转 /login

    Browser->>IdP: POST /login(username, password)
    IdP->>MySQL: 校验用户/写 login_sessions
    IdP->>Redis: 写 session cache
    IdP-->>Browser: Set-Cookie(idp_session) + 302 回 /oauth2/authorize

    Browser->>IdP: 再次 GET /oauth2/authorize
    IdP->>MySQL: 校验 public client / PKCE / redirect_uri / authorization_code
    IdP-->>Browser: 302 到 app callback://cb?code=...&state=...
    Browser-->>App: 回调自定义 scheme / app link

    App->>IdP: POST /oauth2/token(code + code_verifier, auth_method=none)
    IdP->>MySQL: 消费授权码并签发 token
    IdP->>Redis: 写 token cache
    IdP-->>App: access_token / id_token / refresh_token
    App->>App: 安全保存 refresh_token，access_token 用于后续 API 调用
```

## 3. OpenID 认证方式

`openid` 这里按 OIDC Authorization Code 流程画，重点是会返回 `id_token`，并可继续调 `userinfo`。

```mermaid
sequenceDiagram
    autonumber
    participant Client as OIDC Client
    participant Browser as User Browser
    participant IdP as idp-server
    participant MySQL as MySQL
    participant Redis as Redis

    Client-->>Browser: 引导用户跳转到 /oauth2/authorize(scope=openid ...)
    Browser->>IdP: GET /oauth2/authorize
    IdP->>Redis: 查 session

    alt 未登录
        IdP-->>Browser: 302 /login?return_to=...
        Browser->>IdP: POST /login
        IdP->>MySQL: 校验用户/写 session
        IdP->>Redis: 写 session cache
        IdP-->>Browser: 302 回 /oauth2/authorize
    end

    IdP->>MySQL: 校验 client / scope / PKCE / consent
    IdP->>MySQL: 生成 authorization code
    IdP-->>Browser: 302 回 client callback?code=...&state=...
    Browser->>Client: 携带 code 回到客户端
    Client->>IdP: POST /oauth2/token(grant_type=authorization_code)
    IdP->>MySQL: 消费 code，生成 access_token / id_token / refresh_token(可选)
    IdP->>Redis: 写 token cache
    IdP-->>Client: access_token + id_token + expires_in
    Client->>IdP: GET /oauth2/userinfo(Authorization: Bearer access_token)
    IdP-->>Client: sub / name / preferred_username / email
```

## 4. client_credentials 认证方式

```mermaid
sequenceDiagram
    autonumber
    participant ServiceA as Service Client
    participant IdP as idp-server
    participant MySQL as MySQL
    participant Redis as Redis
    participant ServiceB as Resource API

    ServiceA->>IdP: POST /oauth2/token(grant_type=client_credentials)
    Note over ServiceA,IdP: 通过 client_secret_basic 或 client_secret_post 认证 client
    IdP->>MySQL: 校验 client / grant_types / auth_method / scope
    IdP->>MySQL: 落库 access token
    IdP->>Redis: 写 token cache
    IdP-->>ServiceA: access_token(token_type=Bearer, sub=client_id)

    ServiceA->>ServiceB: GET /resource Authorization: Bearer access_token
    ServiceB->>IdP: POST /oauth2/introspect 或本地 JWKS 验签
    IdP-->>ServiceB: active / client_id / scope / sub
    ServiceB-->>ServiceA: 返回受保护资源
```

## 5. API 访问方式

`api` 这里按“客户端拿到 access token 后访问资源服务”来画。资源服务有两条校验路径：本地 JWKS 验签，或回源 introspection。

```mermaid
sequenceDiagram
    autonumber
    participant Client as Web/Mobile/Service Client
    participant API as Resource API
    participant IdP as idp-server

    Client->>API: 请求业务 API + Authorization: Bearer access_token

    alt 本地验 JWT
        API->>IdP: GET /.well-known/openid-configuration
        IdP-->>API: 返回 jwks_uri / issuer / endpoints
        API->>IdP: GET /oauth2/jwks
        IdP-->>API: 返回 JWK Set
        API->>API: 本地验签 + 校验 iss/aud/exp/scope
    else 回源 introspection
        API->>IdP: POST /oauth2/introspect(token)
        IdP-->>API: active / sub / client_id / scope / exp
    end

    API->>API: 根据 scope / subject 做业务授权
    API-->>Client: 返回业务数据
```

## 6. 用户名密码登录

```mermaid
sequenceDiagram
    autonumber
    participant Browser as User Browser
    participant IdP as idp-server
    participant Redis as Redis
    participant MySQL as MySQL

    Browser->>IdP: GET /login?return_to=...
    IdP-->>Browser: 返回登录页
    Browser->>IdP: POST /login(username, password, return_to)
    IdP->>Redis: IP 限流计数
    IdP->>Redis: 用户级失败计数
    IdP->>MySQL: 读取用户/锁定状态
    IdP->>MySQL: 校验 password_hash

    alt 认证成功
        IdP->>MySQL: 写 login_sessions
        IdP->>Redis: 写 session cache
        IdP->>Redis: 清理失败计数
        IdP-->>Browser: Set-Cookie(idp_session) + 302 return_to
    else 认证失败
        IdP->>Redis: 增加失败计数和 TTL
        IdP-->>Browser: 401 或返回登录错误
    end
```

## 7. 联邦 OIDC 登录

```mermaid
sequenceDiagram
    autonumber
    participant Browser as User Browser
    participant IdP as idp-server
    participant Upstream as Upstream OIDC Provider
    participant Redis as Redis
    participant MySQL as MySQL

    Browser->>IdP: 在 /login 选择 federated_oidc
    IdP-->>Browser: 302 跳转到上游 OIDC authorize
    Browser->>Upstream: GET /authorize
    Upstream-->>Browser: 登录/授权页
    Browser->>Upstream: 完成上游登录
    Upstream-->>Browser: 302 回 idp-server callback?code=...&state=...
    Browser->>IdP: GET federated callback
    IdP->>Upstream: 用 code 换 token / userinfo
    Upstream-->>IdP: id_token / access_token / user claims
    IdP->>MySQL: 按 subject -> username -> email 映射本地用户
    IdP->>MySQL: 写本地 login_session
    IdP->>Redis: 写 session cache
    IdP-->>Browser: Set-Cookie(idp_session) + 302 return_to
```

## 8. Consent 授权确认

```mermaid
sequenceDiagram
    autonumber
    participant Browser as User Browser
    participant IdP as idp-server
    participant Redis as Redis
    participant MySQL as MySQL

    Browser->>IdP: GET /oauth2/authorize?...require_consent...
    IdP->>Redis: 查 session
    IdP->>MySQL: 校验 client / redirect_uri / scope
    IdP-->>Browser: 302 /consent?return_to=/oauth2/authorize...

    Browser->>IdP: GET /consent?return_to=...
    IdP->>Redis: 校验 session
    IdP->>MySQL: 解析并校验 return_to 中的 client / redirect_uri / scope
    IdP-->>Browser: 返回 consent 页面

    alt 用户 accept
        Browser->>IdP: POST /consent(action=accept, return_to=...)
        IdP->>MySQL: 写入或更新 oauth_consents
        IdP-->>Browser: 302 回原 /oauth2/authorize
        Browser->>IdP: 再次 GET /oauth2/authorize
        IdP->>MySQL: 生成 authorization_code
        IdP-->>Browser: 302 回 client callback?code=...&state=...
    else 用户 deny
        Browser->>IdP: POST /consent(action=deny, return_to=...)
        IdP-->>Browser: 302 redirect_uri?error=access_denied&state=...
    end
```

## 9. Refresh Token 轮换

```mermaid
sequenceDiagram
    autonumber
    participant Client as Web/Mobile Client
    participant IdP as idp-server
    participant Redis as Redis
    participant MySQL as MySQL

    Client->>IdP: POST /oauth2/token(grant_type=refresh_token, refresh_token=...)
    IdP->>MySQL: 校验 client
    IdP->>Redis: 查 refresh token cache / 吊销态
    IdP->>MySQL: 查 active refresh token
    IdP->>MySQL: 加载 user / client / scope
    IdP->>MySQL: 生成新 access token

    alt client 配置 refresh token TTL > 0
        IdP->>MySQL: 作废旧 refresh token，写 replaced_by_token_id
        IdP->>MySQL: 生成新 refresh token
        IdP->>Redis: 原子 rotation 更新
        IdP-->>Client: 新 access_token + 新 refresh_token
    else 不续发 refresh token
        IdP->>Redis: 写 access token cache
        IdP-->>Client: 新 access_token
    end
```

## 10. 本地 Session 注销

```mermaid
sequenceDiagram
    autonumber
    participant Browser as User Browser
    participant IdP as idp-server
    participant Redis as Redis
    participant MySQL as MySQL

    Browser->>IdP: POST /logout(return_to=...)
    IdP->>Redis: 校验 session / CSRF
    IdP->>Redis: 删除 session cache
    IdP->>MySQL: 标记 login_session.logged_out_at
    IdP-->>Browser: 清理 idp_session cookie + 302 return_to 或 /login
```

## 11. OIDC RP-Initiated Logout

```mermaid
sequenceDiagram
    autonumber
    participant Browser as User Browser
    participant RP as Relying Party
    participant IdP as idp-server
    participant Redis as Redis
    participant MySQL as MySQL

    RP-->>Browser: 跳转到 /connect/logout?client_id=...&post_logout_redirect_uri=...&state=...
    Browser->>IdP: GET /connect/logout
    IdP->>MySQL: 校验 client_id 与 post_logout_redirect_uri 已注册
    IdP-->>Browser: 返回注销确认页
    Browser->>IdP: POST /connect/logout
    IdP->>Redis: 删除 session cache
    IdP->>MySQL: 标记 session logout
    IdP-->>Browser: 清 cookie + 302 post_logout_redirect_uri?state=...
    Browser->>RP: 回到 RP 登出完成页
```

## 12. 动态创建 OAuth Client

```mermaid
sequenceDiagram
    autonumber
    participant Admin as Admin / Internal Caller
    participant IdP as idp-server
    participant MySQL as MySQL

    Admin->>IdP: POST /oauth2/clients(client_id, client_type, grant_types, scopes, redirect_uris...)
    IdP->>IdP: 校验 client_id / client_name / client_type / auth_method
    IdP->>IdP: 校验 public client 必须 PKCE
    IdP->>IdP: 校验 confidential client 不能 auth_method=none
    IdP->>IdP: 校验 redirect_uri / post_logout_redirect_uri / scopes / grant_types
    IdP->>MySQL: 写 oauth_clients
    IdP->>MySQL: 写 redirect_uris / post_logout_redirect_uris / grant_types / scopes
    IdP-->>Admin: 返回 client 元数据
```

## 13. MFA 两阶段认证

```mermaid
sequenceDiagram
    autonumber
    participant Browser as User Browser
    participant IdP as idp-server
    participant Redis as Redis
    participant MySQL as MySQL

    Browser->>IdP: POST /login(username, password)
    IdP->>MySQL: 校验第一因子(password / federated_oidc / WebAuthn)

    alt 该用户不要求 MFA
        IdP->>MySQL: 直接写 login_session
        IdP->>Redis: 写 session cache
        IdP-->>Browser: Set-Cookie(idp_session)
    else 要求 MFA
        IdP->>Redis: 写 pending MFA context(user_id, method, expires_at, nonce)
        IdP-->>Browser: mfa_required=true + mfa_token
        Browser->>IdP: POST /mfa/verify(mfa_token, otp/totp/assertion)
        IdP->>Redis: 校验 pending context
        IdP->>MySQL: 校验第二因子
        IdP->>MySQL: 写正式 login_session(acr, amr_json)
        IdP->>Redis: 删除 pending context + 写 session cache
        IdP-->>Browser: Set-Cookie(idp_session) + 登录完成
    end
```

## 14. 二维码登录

```mermaid
sequenceDiagram
    autonumber
    participant PC as PC Browser
    participant Phone as Mobile App(已登录)
    participant IdP as idp-server
    participant Redis as Redis
    participant MySQL as MySQL

    PC->>IdP: POST /login/qr(return_to=...)
    IdP->>Redis: 写 qr_login_id(status=pending, return_to, expires_at)
    IdP-->>PC: 返回二维码 URL / qr_login_id

    Phone->>IdP: 扫码后 GET /login/qr/:id
    IdP->>Redis: 读取二维码上下文
    IdP-->>Phone: 返回请求摘要(浏览器/时间/应用)

    alt 手机端批准
        Phone->>IdP: POST /login/qr/:id/approve
        IdP->>Redis: 更新状态 approved + approved_by_user_id
        PC->>IdP: 轮询 GET /login/qr/:id
        IdP-->>PC: status=approved
        PC->>IdP: POST /login/qr/:id/consume
        IdP->>Redis: 校验 approved / 未过期 / 未消费
        IdP->>MySQL: 为 PC 创建新的 login_session
        IdP->>Redis: 写 PC session cache + 失效 qr_login_id
        IdP-->>PC: Set-Cookie(idp_session) + 302 return_to
    else 手机端拒绝或过期
        Phone->>IdP: POST /login/qr/:id/reject 或超时
        IdP->>Redis: 更新状态 rejected / expired
        PC->>IdP: 轮询 GET /login/qr/:id
        IdP-->>PC: status=rejected / expired
    end
```

## 15. WebAuthn (Passkey) 注册流程

```mermaid
sequenceDiagram
    autonumber
    participant Browser as Browser (WebAuthn API)
    participant IdP as idp-server
    participant Redis as Redis (MFA Cache)
    participant MySQL as MySQL

    Note over Browser, IdP: 用户已登录，访问 /passkey/setup
    Browser->>IdP: POST /passkey/setup (action=begin)
    IdP->>IdP: 调用 passkey.Service.BeginSetup
    IdP->>Redis: 存储 Registration Session (Challenge 等)
    IdP-->>Browser: 返回 Creation Options (JSON)

    Browser->>Browser: 调用 navigator.credential.create()
    Browser->>IdP: POST /passkey/setup (action=finish, credential_json)
    IdP->>IdP: 调用 passkey.Service.FinishSetup
    IdP->>Redis: 校验并清理 Registration Session
    IdP->>IdP: 使用 go-webauthn 验证 Attestation
    IdP->>MySQL: 存储凭据到 user_webauthn_credentials
    IdP-->>Browser: 注册成功
```

## 16. WebAuthn (Passkey) 登录流程 (作为 MFA)

```mermaid
sequenceDiagram
    autonumber
    participant Browser as Browser (WebAuthn API)
    participant IdP as idp-server
    participant Redis as Redis (MFA Cache)
    participant MySQL as MySQL

    Note over Browser, IdP: 用户完成第一因子登录 (如密码)
    IdP->>MySQL: 查询用户已注册的 Passkeys
    IdP->>Redis: 创建 MFA Challenge (MFAModePasskeyTOTPFallback)
    IdP-->>Browser: 302 /login/totp (提示使用 Passkey 或 TOTP)

    Browser->>IdP: POST /login/totp (action=passkey_begin)
    IdP->>IdP: 调用 authn.Service.BeginMFAPasskey
    IdP->>Redis: 存储 Authentication Session (Challenge 等)
    IdP-->>Browser: 返回 Request Options (JSON)

    Browser->>Browser: 调用 navigator.credential.get()
    Browser->>IdP: POST /login/totp (action=passkey_finish, assertion_json)
    IdP->>IdP: 调用 authn.Service.VerifyMFAPasskey
    IdP->>Redis: 校验并清理 Authentication Session
    IdP->>IdP: 使用 go-webauthn 验证 Assertion
    IdP->>MySQL: 更新凭据最后使用时间
    IdP->>MySQL: 创建正式 login_session (amr=["pwd", "webauthn"])
    IdP-->>Browser: 登录成功，重定向回 return_to
```
