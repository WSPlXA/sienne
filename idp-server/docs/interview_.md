# oauth2-sienne-idp 面试说明

## 1. 项目定位

这个项目不是“写了一个登录接口”，而是实现了一套面向分布式系统的统一认证与授权中心。

它的核心定位可以这样讲：

- 基于 Go 实现 Identity Provider（IdP）
- 支持 OAuth2 + OpenID Connect 主流程
- 统一承载浏览器登录、服务间调用、设备授权、联邦登录和多因素认证
- 面向多服务、多客户端、多实例部署场景设计

面试里最推荐的表述：

> 我设计并实现了一个统一认证与授权中心，基于 OAuth2/OIDC 构建多客户端、多服务的认证体系，支持本地账号、Federated OIDC、MFA（TOTP）、Device Flow、JWT 签发、JWKS 与签名密钥轮转，并通过 Redis + MySQL 共同承载会话、热状态与持久化数据，使系统具备分布式部署能力。

---

## 2. 这个项目为什么加分

### 2.1 能体现的能力

- 安全体系能力：OAuth2/OIDC、JWT、CSRF、防重放、MFA、密钥轮转
- 分布式架构能力：应用无状态、共享 Redis/MySQL、JWT 下沉到资源服务
- 系统设计能力：多种 grant type、会话模型、令牌生命周期、热状态与冷数据分层
- 工程能力：插件式认证、路由分层、Repo/Cache/Service 解耦、Lua 原子脚本

### 2.2 面试官最看重什么

不是“你做了 OAuth2 server”，而是：

- 你实现了哪些流程
- 为什么这样拆存储
- 为什么 JWT 还要配 Redis
- refresh token 为什么要 rotation
- 为什么 TOTP 要做 challenge 而不是直接下发 session
- 哪些地方是强一致，哪些地方是最终一致

一句话：

> 做出来只是及格，讲清设计权衡才是高分。

---

## 3. 已实现能力总览

### 3.1 认证与会话

- 本地注册、登录、登出
- 浏览器 Session（`idp_session`）
- Federated OIDC 登录
- OIDC End Session

### 3.2 OAuth2 / OIDC

- `authorization_code`
- `authorization_code + PKCE`
- `refresh_token`
- `client_credentials`
- `password`（legacy）
- `urn:ietf:params:oauth:grant-type:device_code`
- Discovery
- UserInfo
- Token Introspection
- JWKS

### 3.3 MFA

- TOTP 绑定
- 二步验证登录
- 强制 MFA 入组策略
- TOTP step 防重放

### 3.4 安全控制

- CSRF 双提交校验
- `return_to` 本地路径校验
- Redis 登录失败限流和锁定
- Refresh Token Rotation
- Device Code 轮询频率控制
- 签名密钥轮转

---

## 4. 整体架构怎么讲

### 4.1 架构分层

- Client 层：Browser、SPA、Native App、Device Client、Service Client
- Entry 层：网关或直接进入 IdP
- IdP 应用层：认证、授权、令牌签发、MFA、Federated OIDC
- Persistence 层：MySQL
- Hot State 层：Redis
- Resource Server：校验 JWT 或调用 Introspection

### 4.2 为什么说它是分布式认证中心

因为应用实例本身尽量无状态：

- 会话写入 MySQL + Redis
- 防重放状态放 Redis
- token 是 JWT，可由资源服务分布式校验
- 多个 IdP 实例共享同一套 Redis/MySQL 即可横向扩容

所以更准确的说法是：

> 这是一个为分布式场景设计的认证中心，而不是依赖单机内存 Session 的登录系统。

### 4.3 架构图

```mermaid
flowchart LR
    B["Browser / SPA"] --> G["Gateway / Entry"]
    N["Native App"] --> G
    D["Device Client"] --> G
    S["Service Client"] --> G

    G --> I["IdP Service (Go)"]

    I --> M["MySQL<br/>users / clients / auth codes / refresh tokens / sessions / jwk_keys"]
    I --> R["Redis<br/>session cache / rate limit / lock / oauth state / nonce / mfa challenge / device code"]
    I --> E["External OIDC Provider"]

    I --> RS["Resource Services"]
    RS --> J["JWT validation or Introspection"]
```

---

## 5. 代码结构怎么讲

### 5.1 分层设计

项目采用了比较典型的分层结构：

- `internal/interfaces/http`：HTTP handler、router、dto
- `internal/application`：核心业务服务，编排认证、授权、发 token、MFA
- `internal/domain`：领域模型
- `internal/ports`：仓储、缓存、安全能力的抽象接口
- `internal/infrastructure`：MySQL、Redis、crypto、外部 OIDC 等实现
- `internal/plugins`：grant handler、authn method 等可扩展实现

### 5.2 为什么这样分

这样分层的好处是：

- HTTP 协议细节不会污染核心业务
- Redis / MySQL / 密码学实现可以替换
- grant_type 与认证方式可以插件化扩展
- 更方便做单元测试和面试时讲清职责边界

### 5.3 面试推荐讲法

> 我把接口层、业务层、领域层和基础设施层做了清晰拆分，HTTP 只负责解析和返回，核心逻辑在 application service，中间通过 ports 抽象 repo、cache 和 security provider。这样后面扩展 `password grant`、`device_code`、TOTP，都是在既有边界上增加能力，而不是把逻辑堆在 controller 里。

---

## 6. 关键存储模型怎么讲

### 6.1 MySQL 负责什么

MySQL 负责持久化、审计友好、强一致要求更高的数据：

- `users`
- `login_sessions`
- `oauth_clients`
- `oauth_authorization_codes`
- `oauth_access_tokens`
- `oauth_refresh_tokens`
- `user_totp_credentials`
- `jwk_keys`

### 6.2 Redis 负责什么

Redis 负责热状态、临时状态、高频读写状态：

- session cache
- 登录失败计数与用户锁定
- OAuth `state`
- OIDC `nonce`
- refresh token revoked / rotate 热状态
- TOTP enrollment 临时状态
- MFA challenge
- TOTP step reuse 防重放
- device code 状态与 poll 节流

### 6.3 为什么不用单一存储

因为职责不同：

- 只用 MySQL：高频热状态成本高，实时性与吞吐差
- 只用 Redis：持久化、审计、排障与一致性不足

所以这里的思路是：

> MySQL 存“事实”，Redis 存“热状态和控制面”。

---

## 7. Token 和 Session 设计

### 7.1 为什么选 JWT

JWT 的优点：

- 资源服务本地可验签
- 减少回源认证中心
- 适合微服务和多实例部署

### 7.2 为什么 JWT 还要配 Redis

因为纯 JWT 的缺点是难以及时失效控制。

所以这里是标准生产折中：

- JWT 负责无状态分发
- Redis 负责撤销、黑名单、rotation 热状态
- MySQL 负责持久化 token 记录和追踪链路

### 7.3 本项目里的几类状态

- `access_token`：JWT，给资源服务
- `refresh_token`：长生命周期，支持续期
- `idp_session`：浏览器登录态
- `login_session`：服务端持久化会话记录
- `device_code`：设备授权中间态
- `mfa_challenge`：密码通过但 MFA 尚未完成的临时挑战态

### 7.4 面试推荐说法

> 我的 token 设计不是单纯只发 JWT，而是把 JWT、Redis 和 MySQL 三层配合起来：JWT 用于分布式鉴权，Redis 用于热状态和失效控制，MySQL 负责持久化和审计追踪，这是比较贴近生产的设计。

---

## 8. 支持了哪些 OAuth2 / OIDC 流程

### 8.1 `authorization_code + PKCE`

适用对象：

- Web
- SPA
- Native App

作用：

- 最标准的用户授权流程
- 防止授权码被截获后二次兑换

关键点：

- client 校验
- redirect URI 严格匹配
- scope 白名单校验
- `code_challenge` / `code_verifier` 校验
- code 一次性消费

### 8.2 `refresh_token`

作用：

- 在不让用户重新登录的情况下续期 access token

关键点：

- refresh token 必须绑定 client
- 校验 revoked / expired / active
- 支持 rotation
- 不是简单“旧 token 立刻物理消失”，而是加入短暂 grace period
- 在弱网重试场景下返回第一次成功刷新得到的同一份 token response

### 8.3 `client_credentials`

适用对象：

- 服务间调用
- 机器身份访问

特点：

- 无用户参与
- `sub=client_id`
- 不返回 refresh token

### 8.4 `password`

定位：

- 兼容 legacy 系统
- 不推荐新系统使用

特点：

- 先 client auth
- 再用户口令校验
- 可按 scope 和 refresh 策略发 token

### 8.5 `device_code`

适用对象：

- TV
- 机顶盒
- 输入能力受限的设备

特点：

- 设备申请 `device_code`
- 用户在浏览器完成批准
- 设备按 `interval` 轮询
- 支持 `authorization_pending` / `slow_down` / `access_denied`

### 8.6 Federated OIDC 登录

作用：

- 把外部身份系统接入到本地认证中心

特点：

- 对外部 OIDC Provider 发起授权
- 校验 `state` / `nonce`
- 外部身份回调后映射本地用户
- 最终仍落回本地 session / 本地 token 体系

### 8.7 OIDC 相关接口

- Discovery
- JWKS
- UserInfo
- Introspection

这说明项目不是只有“发 token”，而是把 OIDC 生态里常见的基础接口也补齐了。

---

## 9. 各个登录流程的 Mermaid 时序图

### 9.1 Authorization Code + PKCE

```mermaid
sequenceDiagram
  participant C as Client
  participant B as Browser
  participant I as IdP

  C->>B: 跳转 /oauth2/authorize
  B->>I: GET /oauth2/authorize(client_id, redirect_uri, scope, state, code_challenge)
  I->>I: 校验 client / redirect_uri / scope / PKCE
  alt 未登录
    I-->>B: 302 /login
    B->>I: 完成登录 / TOTP
  end
  alt 需要 consent
    I-->>B: 302 /consent
    B->>I: 提交 consent
  end
  I->>I: 生成一次性 authorization code
  I-->>B: 302 redirect_uri?code=...&state=...
  B->>C: 带回 code
  C->>I: POST /oauth2/token(grant_type=authorization_code, code, code_verifier)
  I->>I: 校验 code + PKCE
  I-->>C: access_token + refresh_token + id_token
```

### 9.2 Refresh Token Rotation

```mermaid
sequenceDiagram
  participant C as Client
  participant I as IdP
  participant R as Redis
  participant M as MySQL

  C->>I: POST /oauth2/token(grant_type=refresh_token, refresh_token)
  I->>I: 校验 client
  I->>R: 检查旧 token 是否已撤销
  I->>M: 查询 refresh token 活跃记录
  alt token 无效
    I-->>C: invalid_grant
  else token 有效
    I->>M: 创建新的 access token
    I->>M: 轮转 refresh token
    I->>R: 原子撤销旧 token 并标记新 token
    I-->>C: access_token + new_refresh_token
  end
```

### 9.2.1 Refresh Token Rotation + Grace Period

```mermaid
sequenceDiagram
  participant C as Client
  participant I as IdP
  participant R as Redis
  participant M as MySQL

  C->>I: POST /oauth2/token(grant_type=refresh_token, old_refresh_token)
  I->>I: 计算 replay fingerprint
  I->>R: 检查 old token 是否处于 rotated + grace 状态
  alt 命中 10 秒宽限期且 fingerprint 一致
    R-->>I: 返回第一次成功刷新缓存的 token response
    I-->>C: 直接返回同一份 access_token + refresh_token
  else 宽限期内 fingerprint 不一致
    I->>R: 标记 token family revoked
    I-->>C: invalid_grant
  else 不在 grace，继续正常刷新
    I->>M: 查 active refresh token
    I->>M: 事务轮转 old -> new
    I->>R: Lua 原子写 rotated_to / grace_until / grace response
    I-->>C: 第一次成功返回新 token 对
  end
```

### 9.3 Client Credentials

```mermaid
sequenceDiagram
  participant S as Service Client
  participant I as IdP
  participant M as MySQL

  S->>I: POST /oauth2/token(grant_type=client_credentials)
  I->>I: client 认证
  I->>M: 校验 client grant / scope / status
  alt 不满足条件
    I-->>S: invalid_client or invalid_scope
  else 校验通过
    I->>M: 持久化 access token
    I-->>S: access_token(sub=client_id)
  end
```

### 9.4 Password Grant

```mermaid
sequenceDiagram
  participant C as Legacy Client
  participant I as IdP
  participant M as MySQL

  C->>I: POST /oauth2/token(grant_type=password, username, password)
  I->>I: client 认证
  I->>M: 校验 client 可用且允许 password grant
  I->>M: 查询用户并校验密码
  I->>M: 校验 scope
  alt 任一步失败
    I-->>C: invalid_client / invalid_grant / invalid_scope
  else 成功
    I->>M: 创建 access token
    opt 支持 offline_access
      I->>M: 创建 refresh token
    end
    I-->>C: access_token (+ refresh_token)
  end
```

### 9.5 Device Code

```mermaid
sequenceDiagram
  participant D as Device Client
  participant U as User Browser
  participant I as IdP
  participant R as Redis

  D->>I: POST /oauth2/device/authorize
  I->>R: 保存 device_code / user_code / interval / status
  I-->>D: device_code, user_code, verification_uri, interval

  U->>I: GET /device?user_code=...
  alt 用户未登录
    I-->>U: 302 /login
    U->>I: 完成登录
  end
  U->>I: POST /device(approve)
  I->>R: 把 device_code 标记为 approved

  loop 按 interval 轮询
    D->>I: POST /oauth2/token(grant_type=device_code, device_code)
    I->>R: 检查状态 + poll 节流
    alt pending
      I-->>D: authorization_pending
    else 轮询过快
      I-->>D: slow_down
    else denied / expired
      I-->>D: access_denied / invalid_grant
    else approved
      I->>R: 标记 consumed
      I-->>D: access_token
    end
  end
```

### 9.6 Federated OIDC Login

```mermaid
sequenceDiagram
  participant U as User Browser
  participant I as Local IdP
  participant R as Redis
  participant E as External OIDC Provider

  U->>I: 点击 Federated Login
  I->>R: 保存 state / nonce
  I-->>U: 302 跳转外部 OIDC
  U->>E: 外部登录
  E-->>U: 302 回调本地 IdP(code, state)
  U->>I: GET /callback
  I->>R: 校验并消费 state / nonce
  I->>E: 用 code 换 token / userinfo
  I->>I: 映射本地用户
  I-->>U: 建立本地 session 并回到 return_to
```

### 9.7 本地登录 + TOTP 二步验证

```mermaid
sequenceDiagram
  participant U as User Browser
  participant I as IdP
  participant R as Redis
  participant M as MySQL

  U->>I: GET /login
  I-->>U: HTML + csrf token
  U->>I: POST /login(username, password, csrf)
  I->>R: 查询失败计数 / 锁状态
  I->>M: 查用户并校验密码
  alt 用户未启用 TOTP 且强制启用
    I-->>U: 302 /mfa/totp/setup
  else 已启用 TOTP
    I->>R: 创建 mfa_challenge
    I-->>U: 302 /login/totp
    U->>I: POST /login/totp(code, csrf)
    I->>R: 读取 mfa_challenge
    I->>R: 校验并保留 TOTP step 只用一次
    I->>M: 创建 login_session
    I->>R: 写 session cache
    I-->>U: Set-Cookie idp_session
  end
```

---

## 10. TOTP / MFA 是怎么做的

### 10.1 为什么要加 TOTP

因为单密码登录存在以下风险：

- 密码泄漏后直接被接管
- 浏览器端登录态一旦被冒用，风险较大
- 面试里也无法体现“高安全级认证设计”

所以 TOTP 的意义是：

- 把认证从单因素升级为多因素
- 给敏感系统提供更强登录保障
- 为后续 step-up authentication 留接口

### 10.2 绑定流程

- 登录后进入 `/mfa/totp/setup`
- 生成 secret 和 provisioning URI
- 页面显示二维码
- 用户用 Authenticator 扫码
- 用户提交一次 6 位验证码
- 服务端校验通过后把 TOTP 凭据持久化到 `user_totp_credentials`

### 10.3 登录二步验证流程

- 第一步：用户名密码校验成功
- 第二步：如果用户已启用 TOTP，则不立刻签发最终 session
- Redis 中创建 `mfa_challenge`
- 跳转到 `/login/totp`
- 验证通过后才创建最终 `idp_session`

### 10.4 为什么要 challenge，而不是直接登录成功

因为密码通过不代表 MFA 完成。

如果密码通过后先签 session，再补 TOTP，会有明显的安全漏洞：

- 攻击者只要拿到密码，就可能先获得部分登录能力
- 会话边界不清晰
- 下游系统难以判断“这次登录是否完成 MFA”

所以更合理的设计是：

> 密码通过后只进入待验证态，TOTP 成功后才发最终 session。

### 10.5 TOTP 防重放怎么做

- 按 `user + purpose + time step` 构造 Redis key
- 用 `SET NX EX` 保证同一 step 只允许成功一次
- `purpose` 分为 `login`、`enable_2fa` 等

这样能防止：

- 同一个 30 秒时间窗内验证码被重复成功使用
- 绑定阶段和登录阶段互相串用

### 10.6 MFA 完成后怎么表达认证强度

可以在 session / token claim 里体现：

- `amr=["pwd","otp"]`
- `acr=urn:idp:acr:mfa`

面试里这是很加分的点，因为说明你考虑的是“认证等级”，而不是只会做表单校验。

---

## 11. CSRF 是怎么做的

### 11.1 当前方案

当前采用 `Double Submit Cookie`：

- 服务端 GET 页面时生成 `idp_csrf_token`
- 一份写 cookie
- 一份放到表单 hidden field 或前端 header
- POST 时比较 cookie 和 body/header 是否一致

### 11.2 为什么先 GET 再 POST

因为浏览器必须先拿到合法 token，之后提交 POST 才能通过校验。

流程本质上是：

1. GET 页面领取 CSRF token
2. POST 提交时回传 token
3. 服务端做 challenge-response 校验

### 11.3 hidden field 是什么

就是表单里的隐藏字段，例如：

```html
<input type="hidden" name="csrf_token" value="server-generated-token">
```

浏览器提交时会自动带上：

```http
POST /login
Cookie: idp_csrf_token=abc

csrf_token=abc&username=alice&password=alice123
```

### 11.4 和服务端 Session CSRF 的区别

Double Submit Cookie：

- 服务端不存 token 状态
- 更轻量
- 更适合当前这种 HTML + 轻 API 场景

Session-based CSRF：

- token 保存在服务端 session
- 控制力更强
- 但要维护更多服务端状态

### 11.5 覆盖了哪些入口

- `/login`
- `/register`
- `/consent`
- `/mfa/totp/setup`
- `/login/totp`
- `/device`
- `/logout`
- `/connect/logout`

---

## 12. XSS / SSRF 怎么讲

### 12.1 XSS 当前做了什么

- 使用服务端模板默认转义
- Session Cookie 使用 `HttpOnly`
- 输入不直接作为原始 HTML 注入
- `return_to` 做本地路径限制，减少开放跳转和参数注入风险

### 12.2 XSS 还缺什么

如果上生产，建议补：

- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `frame-ancestors` 或 `X-Frame-Options`
- `Secure` cookie
- 更严格的模板与富文本输出策略

### 12.3 SSRF 当前风险面在哪里

主要在 Federated OIDC 外呼：

- discovery
- token endpoint
- userinfo endpoint

### 12.4 当前是怎么控制的

- 外呼地址主要来自服务端配置的 issuer
- 不是让用户直接传任意 URL

### 12.5 如果上生产还要怎么做

- issuer 白名单
- 禁止内网 / 回环 / link-local 地址
- 对 discovery 返回的 endpoint 做二次校验
- 网络层出站白名单
- DNS rebinding 防护

面试推荐说法：

> 当前 SSRF 风险面主要集中在联邦 OIDC 外呼，我已经通过服务端配置收敛了输入来源，但如果上生产还会补 issuer 白名单、私网地址拦截、discovery 结果校验以及网络层出站访问控制。

---

## 13. 防重放怎么讲

这个项目不是“只有一个 nonce”，而是分凭证做多层防重放。

### 13.1 Authorization Code

- code 一次性消费
- `consumed_at`
- 事务或锁保证只可兑换一次

### 13.2 OIDC `state`

- Redis 中只允许首次写入
- 回调成功后立即消费

### 13.3 OIDC `nonce`

- `SET NX EX`
- 保证同 nonce 只保留一次

### 13.4 Refresh Token

- rotation
- 旧 token 被替换后进入短暂 grace period，而不是立刻完全不可识别
- 10 秒内同一 fingerprint 的合法重试会返回第一次成功刷新得到的同一份 token response
- 10 秒外重放，或宽限期内 fingerprint 不一致，会被识别为 replay 并失败

### 13.4.1 为什么要加 Grace Period

因为真实客户端并不总是工作在理想网络下。

如果第一次刷新实际上已经成功了，但客户端在弱网、超时、连接复用异常的情况下没收到响应，就会自然重试。  
如果服务端把“旧 refresh token 只要被消费过一次就立刻统一打成 invalid_grant”，会出现两个问题：

- 合法客户端被自己重试打死
- 用户看到的是随机失效，而不是平滑续期

所以更贴近 Auth0 / Okta 这类业界实践的方案是：

- 第一次成功刷新后，旧 token 进入很短的 grace period
- 宽限期内不再派生第二个 child token
- 如果请求来源与第一次刷新一致，就返回第一次成功的那一份结果
- 如果来源不一致，则视为可疑 replay

### 13.4.2 当前实现怎么做

我把这件事拆成了三层：

- MySQL：持久化 refresh token 事实记录和 rotation 链
- Redis：保存 `rotated` 热状态、`grace response`、family revoke 标记
- Lua：原子判断和写入 grace 相关状态

Redis 侧大致有三类 key：

- `token:refresh:sha256:<sha>`
- `token:refresh:grace:<old_sha>`
- `token:refresh:family:revoked:<family_id>`

旧 token 第一次成功刷新后，会被写成：

- `status=rotated`
- `rotated_to=<new_sha>`
- `grace_until=<now+10s>`
- `bind_fp=<replay_fingerprint>`
- `family_id=<family_id>`

同时 Redis 会缓存第一次成功刷新返回的 token response，TTL 约 10 秒。

### 13.4.3 replay fingerprint 是什么

为了区分“合法弱网重试”和“真正的盗用重放”，我在 token endpoint 会计算一个短指纹：

- `client_id`
- client auth method
- client IP
- user agent

当前它不是最终形态的 sender-constrained token 方案，但已经能把“同一客户端的幂等重试”和“不同来源的重放”区分开。

如果继续往生产级推进，下一步会升级成：

- mTLS 证书指纹
- 或 DPoP `jkt`

### 13.4.4 Lua 脚本是怎么判断的

现在 refresh rotation 不是单一脚本直接“一把梭”完成，而是拆成两段：

1. `check_refresh_replay.lua`
   - 先看旧 token 是否已经处于 `rotated + grace` 状态
   - 如果命中 grace 且 fingerprint 一致，直接返回缓存 response
   - 如果 fingerprint 不一致，或 grace 已经过期还重放，就标记 family revoke

2. `rotate_token.lua`
   - 首次消费时把旧 token 从 `active` 切到 `rotated`
   - 写入 `grace_until`
   - 写入第一次成功刷新得到的 response 缓存
   - 保存新 token hash 状态

这样做好处是：

- 合法重试可幂等
- 恶意 replay 可识别
- 旧 token 不会在宽限期内继续派生第二份 child token

### 13.4.5 为什么还要改数据库事务

光有 Redis 不够，因为并发下可能出现：

- 两个请求几乎同时读到同一个 active refresh token
- 都准备插入新的 child token

所以我在 MySQL 的 `RotateRefreshToken` 事务里也补了检查：

- old token 已被 revoke
- 或已经有 `replaced_by_token_id`
- 或已经过期

这种情况下事务会直接失败，然后上层回退去检查 grace replay，而不是再长出第二个 child token。

### 13.5 TOTP

- 按 step 一次性使用

### 13.6 Device Code

- 状态机控制 `pending -> approved/denied -> consumed`
- 签发 token 后立即 consumed

面试里最好不要只说“做了防重放”，而要说：

> 我把不同类型的凭证分别做了重放控制，因为 authorization code、refresh token、TOTP 和 device code 的生命周期、风险面和一致性要求并不一样。

---

## 14. JWT 与签名密钥轮转怎么讲

### 14.1 为什么不是固定密钥

固定私钥长期使用的问题：

- 泄漏后影响范围大
- 无法平滑更新
- 不利于多实例和长期运维

### 14.2 现在怎么做

- 使用 `RS256`
- 当前 active key 签发新 token
- 通过 `kid` 标识签名 key
- 公钥通过 `/oauth2/jwks` 发布
- 资源服务按 `kid` 获取对应 JWK 验签

### 14.3 轮转过程

- 生成新 RSA key
- 私钥写到文件
- 公钥转成 JWK 入库
- 新 key 设为 active
- 旧 key 在 `RetireAfter` 窗口后退役

### 14.4 为什么要保留旧 key 一段时间

因为旧 token 还在有效期内。

如果立刻删除旧 key，会导致：

- 老 token 无法验签
- 多服务出现短时认证雪崩

所以标准做法是：

> 新旧 key 共存一段时间，等待旧 token 自然过期后再退役旧 key。

---

## 15. 登录接口能不能扛高并发

### 15.1 结论

现在这套登录接口具备一定并发能力，但更准确的表述是：

> 中等并发可用，离“高并发登录入口”还有优化空间。

### 15.2 优点

- 应用层基本无状态，可横向扩容
- Redis 承担失败计数、锁定、session cache
- MySQL 和 Redis 职责分层明确
- 没有单机内存 session 锁死在单节点

### 15.3 主要瓶颈

- bcrypt 校验吃 CPU
- 登录成功链路同步写 MySQL + Redis
- MySQL 连接池会成为硬瓶颈
- 高峰期失败流量会放大风控和数据库压力

### 15.4 高并发改造优先级

1. MySQL 连接池改成可配置并调大
2. 网关和应用层增加登录限流
3. 把非关键写操作异步化
4. 对 bcrypt 做容量测试和成本治理
5. Redis 优化热路径与原子脚本

### 15.5 面试建议回答

> 我不会直接说登录接口能扛高并发，而是会先拆瓶颈：CPU 在密码哈希，IO 在 MySQL 和 Redis，同步写会影响 RT。当前架构支持横向扩容，但要真正做到高并发登录入口，还需要连接池治理、入口限流、热路径异步化和压测基线建设。

---

## 16. grant_type 具体实现到什么程度

### 16.1 已落地的 grant

- `authorization_code`
- `refresh_token`
- `client_credentials`
- `password`
- `urn:ietf:params:oauth:grant-type:device_code`

### 16.2 为什么这是加分点

因为不是只做了一个 happy path，而是把不同客户端场景都建模了：

- 浏览器和原生应用：`authorization_code + PKCE`
- 服务间：`client_credentials`
- 历史系统：`password`
- 受限输入设备：`device_code`
- 长会话续期：`refresh_token`

### 16.3 面试里怎么说

> 我不是只实现了单一 grant，而是把典型人类用户、设备端、服务端和遗留系统的接入方式都纳入进来，并且每种 grant 都分别做了自己的约束校验和生命周期控制。

---

## 17. 为什么 Obsidian / Native App 先 password，再 TOTP

因为 TOTP 是第二因子，不是第一因子。

认证顺序一般是：

1. 先确认“你是谁”
2. 再确认“你是否持有绑定设备”

也就是：

- 第一因子：用户名密码
- 第二因子：TOTP

所以像 Native App、桌面客户端接入认证中心时，仍然会先看到 password challenge，再进入 TOTP challenge。

### 17.1 哪些 client 适合接 TOTP

适合：

- Web Client
- Native App
- SPA
- Device Flow 中的浏览器确认端

不适合直接接：

- `client_credentials` 这种纯机器客户端

因为机器客户端没有“人类第二因子”的概念。

---

## 18. 为什么 TOTP 值得做

因为做了 TOTP 以后，项目定位会从：

- “有 OAuth2 server 的登录系统”

升级成：

- “企业级统一认证与授权中心”

它体现的能力包括：

- MFA 设计
- Challenge 状态管理
- 二步登录链路
- 认证强度表达（`amr` / `acr`）
- 未来 step-up authentication 扩展能力

---

## 19. 设计模式和工程拆分怎么讲

### 19.1 责任链

认证和校验链路天然适合责任链，比如：

- 解析请求
- 校验 CSRF
- 校验登录限流
- 校验用户名密码
- 判断是否需要 MFA
- 校验 TOTP
- 创建 session

### 19.2 策略模式

适合多种认证来源和 grant type：

- password auth method
- federated OIDC auth method
- authorization_code grant handler
- refresh_token grant handler
- password grant handler
- device_code grant handler

### 19.3 好处

- 增加一个 grant 不需要改大段 if-else
- 增加一种认证方式时边界清楚
- 代码更适合演进和测试

---

## 20. 你必须能回答的高频追问

### 20.1 JWT 怎么失效

- 短过期时间
- refresh token 续期
- Redis revoked / blacklist 控制

### 20.2 为什么不用纯 Session

- JWT 更适合微服务
- 资源服务本地可验证
- 降低对认证中心的强依赖

### 20.3 为什么不用纯 JWT

- 纯 JWT 难做实时失效
- 难做 rotation 和撤销控制
- 所以要配 Redis 和持久化记录

### 20.4 如何防止 token 被盗

- HTTPS
- HttpOnly Cookie
- 短 access token TTL
- refresh token rotation
- 生产环境可继续加设备/IP 绑定

### 20.5 为什么 password grant 不推荐

- client 能直接接触用户密码
- 安全边界较差
- 新系统应优先 `authorization_code + PKCE`

### 20.6 为什么 Device Flow 要 slow_down

- 防止设备端过快轮询打爆服务
- 强制设备遵守服务端 interval

### 20.7 为什么 refresh token 要 rotation

- 防止 refresh token 泄漏后长期复用
- 一旦旧 token 被再次使用，可以识别为异常路径

### 20.7.1 为什么不是“旧 refresh token 立刻直接报废”

如果只做最朴素的 rotation，旧 refresh token 一旦第一次成功消费，后续再来统一返回 `invalid_grant`。  
这在理想网络里没问题，但真实场景下会误伤弱网客户端。

所以更合理的做法是：

- 第一次刷新成功后保留一个极短 grace period
- 10 秒内同一客户端的幂等重试，直接返回第一次成功的那一份 token response
- 不再次签发新的 refresh token

这样既能平滑处理重试，又不会放大 token fan-out。

### 20.7.2 如何区分“合法重试”和“黑客重放”

不能只看“是不是 10 秒内”，还要看请求来源约束。

我现在的做法是计算一个 replay fingerprint，至少绑定：

- `client_id`
- client auth method
- IP
- user agent

判断规则是：

- 宽限期内 + fingerprint 一致：返回第一次成功刷新结果
- 宽限期内 + fingerprint 不一致：视为可疑 replay
- 宽限期结束后再次使用旧 token：视为 replay

### 20.7.3 replay 发生后怎么处理

对于真正可疑的 refresh token replay，不能只返回一次 `invalid_grant` 就算了，更合理的是：

- 直接让当前旧 token 失败
- 标记该 refresh token family 为 revoked
- 后续同 family 链路继续请求时一并拒绝
- 记录安全审计事件

这比“只撤销当前这一个旧 token”更稳，因为真正的盗用往往意味着整条 family 都不可信了。

### 20.7.4 面试推荐标准回答

> 我对 refresh token 不是只做了最基础的 rotation，而是补成了带 grace period 的生产化方案。第一次成功刷新后，旧 token 不会再继续派生新的 child token，但会进入大约 10 秒的宽限期；如果客户端因为弱网超时重试，并且 replay fingerprint 与第一次请求一致，服务端会直接返回第一次成功刷新得到的同一份 token response。反过来，如果宽限期内 fingerprint 不一致，或者宽限期结束后仍重放旧 token，我会把它判定为 replay，并进一步撤销整个 token family。这样既兼顾了安全性，也兼顾了真实客户端的幂等重试体验。

### 20.8 为什么 MFA 先 challenge，再发 session

- 保证未完成 MFA 前没有最终登录态
- 认证边界更清晰
- 方便在 `amr` / `acr` 中表达认证等级

---

## 21. 一分钟项目介绍

> 我做的是一个基于 Go 的统一认证与授权中心，核心实现了 OAuth2 和 OpenID Connect 主流程，包括 authorization code + PKCE、refresh token、client credentials、password grant 和 device code。架构上采用 MySQL 做持久化、Redis 做热状态和防重放，access token 使用 JWT，并提供 JWKS、Introspection 和签名密钥轮转。除了基本登录，我还实现了 Federated OIDC 和 TOTP 多因素认证，使它不仅是一个能发 token 的服务，而是一套更接近企业级的认证平台。

---

## 22. 三分钟项目介绍

> 这个项目的目标不是简单做一个登录接口，而是实现一个面向分布式系统的统一认证中心。首先在协议层面，我把 OAuth2 和 OIDC 的主流程都补齐了，包括 authorization code + PKCE、refresh token rotation、client_credentials、password grant 和 device code，同时还支持 Discovery、UserInfo、JWKS 和 Introspection。  
>   
> 在架构上，我把状态做了分层：MySQL 存持久化事实，比如用户、客户端、授权码、refresh token、session 和 JWK；Redis 存高频热状态，比如登录失败计数、用户锁定、OAuth state、nonce、refresh token rotation 热状态、MFA challenge 和 device code 状态。这样应用实例本身可以尽量无状态，更适合多实例部署。  
>   
> 安全上我重点做了几件事：第一是 CSRF 双提交校验，第二是针对 authorization code、refresh token、TOTP 和 device code 分别做防重放，第三是 JWT 的签名密钥轮转和 JWKS 发布，第四是加了 TOTP 多因素认证。TOTP 不是简单多一个验证码输入框，而是做成了 challenge 流程，密码通过后先进入待验证态，TOTP 成功后才创建最终 session，同时还能通过 amr/acr 表达认证强度。  
>   
> 所以这个项目我会把它定义成统一认证与授权平台，而不是普通的登录模块。它体现的不只是接口实现，还有协议理解、安全设计、状态管理和分布式架构能力。

---

## 23. 简历写法

### 23.1 推荐版本

> 设计并实现统一认证与授权中心，基于 OAuth2/OIDC 构建多客户端、多服务认证体系，支持 Authorization Code + PKCE、Refresh Token Rotation、Client Credentials、Device Flow、Federated OIDC 与 TOTP MFA；采用 JWT 无状态鉴权结合 Redis 热状态控制与 MySQL 持久化存储，实现会话管理、防重放、签名密钥轮转与 JWKS 发布，支持分布式部署与统一接入。

### 23.2 如果要更偏工程实现

> 基于 Go 设计并落地企业级 IdP，完成 grant handler、认证链路、MFA challenge、Redis Lua 原子脚本、防重放控制、JWT/JWKS/Key Rotation 等核心实现，并通过接口分层和可扩展插件机制支持多种认证与授权模式演进。

---

## 24. 后续还能继续升级什么

### 24.1 云原生

- K8s 部署
- HPA
- Gateway 统一鉴权
- 灰度发布与熔断

### 24.2 安全增强

- CSP 与安全响应头
- Secret 加密存储
- TOTP recovery codes
- Step-up authentication
- 更完整审计日志

### 24.3 分布式增强

- 独立的 key management 控制面
- 分布式锁保护 key rotation
- 更细粒度的租户与权限模型
- 统一 Audit Event pipeline

---

## 25. 最后总结

这个项目真正的价值，不在于“做了 OAuth2 server”，而在于它已经具备了下面这些工程级能力：

- 协议实现：OAuth2 / OIDC 主流程比较完整
- 安全设计：CSRF、防重放、MFA、密钥轮转
- 分布式能力：JWT + Redis + MySQL + 多实例友好
- 系统设计：多 grant、多客户端、多存储层职责拆分
- 可扩展性：插件化 grant、认证方式、基础设施抽象

最后一句面试收尾推荐这样说：

> 我把这个项目定义为统一认证与授权中心，而不是单纯的 OAuth2 Demo。它真正体现的是协议理解、安全设计、分布式状态管理和工程化落地能力。

---

## 26. RBAC 怎么讲

### 26.1 为什么还要单独做 RBAC

这个 RBAC 不是给 OAuth2 `scope` 用的，而是给后台管理接口、运维接口和管理员操作用的。

要区分这几件事：

- `scope`：协议层授权语义，例如 `openid`、`profile`
- `role_code`：角色标签，例如 `support`、`oauth_admin`
- `privilege_mask`：真正用于接口鉴权的 32 位权限位
- `tenant_scope`：数据边界，不是权限本身

面试里最好主动强调：

> 我没有把 OAuth scope 和后台管理权限混在一起，而是单独设计了一套后台 RBAC，用来控制管理接口、运维动作和高危操作。

### 26.2 32 位权限位结构

我采用的是 8 个权限域，每个权限域 4 bit：

```text
[31........28][27........24][23........20][19........16][15........12][11.........8][7..........4][3..........0]
   AUTH           OAUTH         CLIENT         USER         AUDIT          KEY           TENANT         OPS
```

每个 4 bit 的统一语义：

- `READ = 8`
- `EXEC = 4`
- `MANAGE = 2`
- `PRIV = 1`

也就是：

- `READ`：查列表、看详情、看状态
- `EXEC`：执行普通动作
- `MANAGE`：改配置、改资源
- `PRIV`：高危动作、破坏性动作、越权动作

### 26.3 8 个权限域含义

- `AUTH`：登录、session、MFA、challenge、锁定状态
- `OAUTH`：authorize、token、consent、device flow、introspect
- `CLIENT`：OAuth client、redirect URI、grant type、secret
- `USER`：用户账号、管理员账号、账号状态
- `AUDIT`：审计日志、安全事件、报表
- `KEY`：签名密钥、JWKS、轮转、证书
- `TENANT`：租户、组织、隔离边界
- `OPS`：平台配置、运维动作、全局开关、应急操作

### 26.4 为什么这样切

因为后台权限模型最怕后面越做越乱。

统一做法的好处是：

- 权限语义一致，接口判断简单
- 角色只是权限掩码的聚合，不绑死逻辑
- 容易扩展运营后台和管理 API
- 高危权限位可以单独重点管控

---

## 27. RBAC 在项目里落到了什么程度

### 27.1 用户模型

现在用户模型已经有：

- `role_code`
- `privilege_mask`
- `tenant_scope`

这意味着：

- 用户有角色标签
- 用户有真实权限位
- 后续还能扩数据范围控制

### 27.2 角色模型

项目里已经新增 `operator_roles` 表，存这些内容：

- `role_code`
- `display_name`
- `description_text`
- `privilege_mask`
- `is_system`

也就是说系统已经支持：

- 内置系统角色
- 自定义角色
- 角色列表查询
- 角色 CRUD

### 27.3 内置角色

当前已经有几类预设角色：

- `end_user`
- `support`
- `oauth_admin`
- `security_admin`
- `super_admin`

面试里可以讲成：

> 我没有只把权限码定义成常量，而是把角色预设持久化到了数据库里，支持初始化、查询和后续运营管理。

---

## 28. RBAC 接口怎么讲

### 28.1 角色初始化与管理

已经有这些接口：

- `GET /admin/rbac/roles`
- `POST /admin/rbac/bootstrap`
- `POST /admin/rbac/roles`
- `PUT /admin/rbac/roles/:role_code`
- `DELETE /admin/rbac/roles/:role_code`

### 28.2 用户角色分配

- `POST /admin/users/:user_id/role`

支持：

- 给用户绑定角色
- 可选覆盖 `privilege_mask`
- 可带 `tenant_scope`

### 28.3 角色运营查询

为了让后台真正可运营，还补了：

- `GET /admin/rbac/roles/:role_code/users`
- `GET /admin/rbac/usage`

也就是：

- 能看某个角色下面有哪些用户
- 能看每个角色当前用了多少人

### 28.4 强制下线能力

RBAC 不是单独摆在那里的，我已经把它接到了真正高价值的管理动作上：

- `POST /admin/users/:user_id/logout-all`

这个接口会：

- 注销该用户全部 session
- 删除 Redis session cache
- 撤销活跃 access token / refresh token

这在面试里是很加分的，因为说明权限系统已经接到了真实管理动作，而不是停留在只读配置。

---

## 29. RBAC 鉴权链路怎么讲

### 29.1 当前鉴权方式

管理接口不是走 Bearer token，而是走浏览器 `idp_session`：

1. 读取 `idp_session`
2. 查 session cache / session repository
3. 找到当前登录管理员用户
4. 读取用户的 `privilege_mask`
5. 判断是否满足接口所需权限位

### 29.2 当前接口上的权限要求

例如：

- 角色管理接口要求更高一级的 `OPS.MANAGE`
- 用户管理相关接口要求 `AUTH.EXEC + USER.MANAGE`

这类判断不再依赖模糊的“是不是管理员”，而是精确到权限位。

### 29.3 面试推荐说法

> 我的管理接口鉴权不是简单判断一个 `is_admin`，而是先从 session 识别当前管理员，再读取其 32 位 `privilege_mask`，按接口声明的权限位做校验。这样角色只是权限集合，接口真正绑定的是能力，而不是职位名称。

---

## 30. RBAC 里的关键约束

为了避免后台权限系统把自己玩坏，我加了几个约束：

- 系统内置角色不可删除
- 系统内置角色不可直接更新
- 删除角色前会检查是否仍有用户在使用
- 角色码有固定格式约束
- 显示名和描述有长度约束

这些约束的价值是：

- 避免运营误删系统关键角色
- 避免配置漂移
- 防止角色定义和用户绑定脱节

面试里你可以说：

> 权限系统最怕只考虑“怎么加”，不考虑“怎么防误操作”。所以我对系统角色做了不可变约束，对删除动作加了引用检查，让 RBAC 更接近生产系统的控制面。

---

## 31. RBAC 和权限设计高频追问

### 31.1 为什么不用字符串权限

可以用，但位掩码的优势是：

- 判定快
- 存储紧凑
- 角色聚合自然
- 做权限组合和高危位控制更方便

### 31.2 为什么角色和权限码要并存

因为：

- `role_code` 方便运营理解
- `privilege_mask` 方便程序判断

角色更像“人类可读标签”，权限位才是真正的鉴权依据。

### 31.3 为什么不把 tenant scope 塞进权限位

因为数据范围不是动作权限。

例如：

- 能不能改用户，是权限问题
- 能改哪个租户的用户，是数据范围问题

这两个维度必须分开。

### 31.4 最危险的权限位有哪些

应该重点收紧：

- `KEY.PRIV`
- `OPS.PRIV`
- `AUTH.PRIV`
- `OAUTH.PRIV`
- `AUDIT.PRIV`

因为这些位一旦乱给，可能导致：

- 跳过 MFA
- 人工签 token
- 导出私钥
- 删除审计记录
- 全局撤销 token

---

## 32. 面试里怎么总结 RBAC

推荐你这样说：

> 在协议层授权之外，我又单独设计了一套后台 RBAC，用于控制管理员和内部操作接口。具体上我采用 32 位权限位，把权限拆成 8 个域，每个域用 READ/EXEC/MANAGE/PRIV 4 bit 描述动作强度。系统里既有内置角色，也支持自定义角色、角色 CRUD、用户赋权、按角色查用户和角色使用情况统计。管理接口通过 session 识别当前管理员，再按 `privilege_mask` 做精细化鉴权，例如角色管理、强制下线用户等动作都会校验对应权限位。这样角色只是权限集合，而鉴权真正绑定的是能力本身。 

### 32.1 RBAC 和审计怎么联动

我没有把 RBAC 只做到“能拦接口”就停下，而是把关键管理动作接进了 `audit_events`：

- 角色创建
- 角色更新
- 角色删除
- 用户赋权
- 管理员强制某用户全端下线

这些审计事件会记录：

- `event_type`
- 操作者 `user_id`
- 当前管理 session
- 目标对象 `subject`
- `ip_address`
- `user_agent`
- `metadata_json`

例如赋权时会记录目标用户、角色编码、权限掩码、租户范围；踢人时会记录被下线用户以及撤销的 session / access token / refresh token 数量。

面试里可以这样讲：

> 我在后台控制面里把 RBAC 和审计系统做了联动。也就是说，系统不仅能判断“谁有权做什么”，还能追踪“谁在什么时候，对哪个对象做了什么变更”。像角色 CRUD、用户赋权、管理员强制下线这类高价值动作，我都会写入 `audit_events`，记录操作者、目标对象、IP、UA、session 和业务元数据，这样后续做安全审计、故障排查和合规追踪都有依据。

---

## 33. 2026-04-09 更新补充（控制面与认证链路）

下面这部分是最近一批更新，面试里可以作为“持续演进能力”的证据来讲。

### 33.1 控制面入口与分角色工作台

新增控制面导航入口和分角色工作台，路由已落地：

- `/`：Portal 首页，按权限域和角色引导入口
- `/admin/workbench/support`
- `/admin/workbench/oauth`
- `/admin/workbench/security`

这让后台不再只是“接口列表”，而是按角色职责组织操作路径。

### 33.2 管理动作统一收口到 `/admin/actions/*`

新增一组表单友好的控制面动作接口，全部走 CSRF + RBAC + 审计：

- `/admin/actions/rbac/bootstrap`
- `/admin/actions/rbac/roles/create`
- `/admin/actions/rbac/roles/update`
- `/admin/actions/rbac/roles/delete`
- `/admin/actions/users/assign-role`
- `/admin/actions/users/logout-all`
- `/admin/actions/users/change-password`
- `/admin/actions/keys/rotate`
- `/admin/actions/clients/create`
- `/admin/actions/clients/redirect-uris`
- `/admin/actions/clients/post-logout-redirect-uris`

可以在面试里强调：

> 我把管理平面的关键写操作集中在 `/admin/actions/*`，统一校验 CSRF 与权限位，并把高价值动作写入审计事件，避免管理能力散落在多个入口。

### 33.3 注册与客户端管理权限收紧

安全边界做了明确收敛：

- `/register` 现在默认走管理员权限控制（`AUTH.EXEC + USER.MANAGE`）
- 如果 admin middleware 不可用，`/register` 明确返回“disabled”而不是放开
- `/oauth2/clients*` 在 middleware 可用时要求 `CLIENT.MANAGE`

这说明系统从“开放演示接口”转向“受控管理接口”。

### 33.4 Admin 会话强制 MFA

后台权限中间件新增强约束：

- 仅有 `idp_session` 不够
- 还要求会话达到 MFA 条件（`amr` 包含 `otp` 或 `acr=urn:idp:acr:mfa`）

也就是说后台不接受“弱会话”直接进控制面。

### 33.5 用户检索与密码重置闭环

控制面补了账号运维高频动作：

- `GET /admin/users/lookup-by-username`
- `POST /admin/actions/users/change-password`

并在持久层新增了密码哈希更新 SQL（同时把失败计数清零）：

- `update_password_hash.sql`

这让“定位用户 -> 修改密码 -> 强制下线”形成可闭环的运维路径。

### 33.6 手动密钥轮转控制面化

新增 keys service 和手动轮转动作：

- `POST /admin/actions/keys/rotate`

返回与审计会携带：

- `previous_kid`
- `active_kid`
- `rotated_at`
- `next_rotate_at`（若可用）

面试里可讲成“把密钥轮转从定时任务升级为可控的应急操作”。

### 33.7 MFA 链路扩展到 Passkey / Push 模式

认证链路在 TOTP 基础上扩展了多模式挑战上下文：

- `/mfa/passkey/setup`（WebAuthn 注册 begin/finish）
- `/login/totp` 支持 `passkey_begin` / `passkey_finish` / `poll` / `approve` / `deny`
- `/mfa/push` 提供 push 决策入口
- 登录返回增加 `mfa_mode`、`passkey_available`、`push_status`、`push_code`

数据库也新增了 passkey 凭据表：

- `user_webauthn_credentials`

建议在面试里讲“多因子挑战状态机已抽象为可扩展模式，而不是硬编码单一 TOTP 页面”。

### 33.8 配置与部署面更新

新增/强化的配置项：

- `TOTP_ISSUER`
- `PASSKEY_ENABLED`
- `PASSKEY_RP_ID`
- `PASSKEY_RP_DISPLAY_NAME`
- `PASSKEY_RP_ORIGINS`

`compose.quickstart.yaml` 也同步了 Nginx 前置、HTTPS 发行者默认值与 Passkey RP 参数，方便更贴近生产的接入验证。

---

## 34. 这一轮更新在面试里的价值

可以总结为三点：

- 从“协议功能可用”升级到“控制面可运营”
- 从“管理员角色可配”升级到“高危动作可审计、可回溯”
- 从“单一 MFA”升级到“多因子模式化挑战框架（TOTP/Passkey/Push）”

简短说法：

> 最近一次迭代我重点做了控制面能力和安全边界收敛：把高危管理动作收口到 `/admin/actions/*` 并全量审计；把注册和客户端管理切到权限控制；把后台入口升级成必须 MFA 会话；同时把 MFA 扩展成 TOTP + Passkey + Push 的模式化挑战链路。

---

## 35. 你可以主动提的一个“工程诚实点”

当前路由能力已经超过 OpenAPI 文档覆盖范围（比如控制面和部分 MFA 扩展端点），面试里可以主动说明：

> 我们优先把控制面能力落地到了代码和路由层，后续会把 OpenAPI 同步补齐，避免文档契约滞后。
