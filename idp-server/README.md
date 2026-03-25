# idp-server Local Client Reference

这个文档只讲一件事：当你在本机写一个桌面端、SPA 外壳、或本地 Web 客户端时，怎么正确接这个 IdP。

## 基本结论

- 客户端自己不要渲染登录页。
- 未认证时，客户端只做 `302` 到 IdP 的 `/oauth2/authorize`。
- 真正的登录页面由 IdP 的 `GET /login` 提供。
- 客户端回调拿到 `code` 后，再去 `POST /oauth2/token`。
- 联动登出不要代打 `POST /logout`，应让浏览器导航到 `GET /connect/logout`。

## 当前支持的能力

- Authorization Code + PKCE
- Refresh Token
- Client Credentials
- OIDC Discovery: `/.well-known/openid-configuration`
- JWKS: `/oauth2/jwks`
- UserInfo: `/oauth2/userinfo`
- Introspection: `/oauth2/introspect`
- Browser-facing end session: `/connect/logout`

## 当前还没有的能力

- Token revocation endpoint
- Device Code flow
- Dynamic Client Registration 标准实现
- Back-channel / front-channel logout
- 完整 OIDC RP-Initiated Logout 参数集（当前不是 `id_token_hint` 驱动）

## 本地开发默认地址

默认配置来自环境变量和种子数据：

- IdP issuer: `http://localhost:8080`
- 示例机密客户端: `web-client`
- 示例资源侧客户端回调: `http://localhost:8081/callback`
- 示例 post logout redirect: `http://localhost:8081/`

如果你改了端口，必须同步改客户端白名单。这里是严格字符串匹配：

- `localhost` 和 `127.0.0.1` 不等价
- 端口不同不等价
- 多一个 `/` 也不等价
- 带 `#fragment` 的 URI 会被拒绝

## 浏览器登录流

### 1. 未登录时跳到 authorize

客户端应构造：

```text
GET http://localhost:8080/oauth2/authorize?
  response_type=code&
  client_id=web-client&
  redirect_uri=http://localhost:8081/callback&
  scope=openid%20profile%20email&
  state=<random>&
  code_challenge=<pkce_challenge>&
  code_challenge_method=S256
```

要求：

- `state` 必须随机，客户端自己保存并在 callback 时校验。
- `code_verifier` 必须随机，客户端自己保存。
- `code_challenge_method` 目前支持 `plain` 和 `S256`，本地客户端直接用 `S256`。

### 2. IdP 判断会话

IdP 行为：

- 已有 `idp_session`：继续授权流程
- 没有 `idp_session`：`302` 到 `GET /login?return_to=<原 authorize 请求>`

所以登录页属于 IdP，不属于你的客户端。

### 3. 回调换 token

客户端收到：

```text
GET /callback?code=<code>&state=<state>
```

客户端必须：

- 校验 `state`
- 用保存的 `code_verifier` 调 token endpoint

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -u web-client:web-client-secret \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<code>" \
  -d "redirect_uri=http://localhost:8081/callback" \
  -d "code_verifier=<original-code-verifier>"
```

> `web-client` 的真实 secret 以你当前环境为准；种子数据里存的是 hash，不会回显。

## 如何注册客户端白名单

### 注册 redirect URI

```bash
curl -X POST http://localhost:8080/oauth2/clients/web-client/redirect-uris \
  -H "Content-Type: application/json" \
  -d '{"redirect_uri":"http://localhost:8081/callback"}'
```

### 注册 post logout redirect URI

```bash
curl -X POST http://localhost:8080/oauth2/clients/web-client/post-logout-redirect-uris \
  -H "Content-Type: application/json" \
  -d '{"redirect_uri":"http://localhost:8081/"}'
```

也可以在创建 client 时一次性带上：

```json
{
  "client_id": "desktop-client",
  "client_name": "Desktop Client",
  "client_type": "public",
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile", "offline_access"],
  "redirect_uris": ["http://127.0.0.1:8787/callback"],
  "post_logout_redirect_uris": ["http://127.0.0.1:8787/"]
}
```

## 联动登出

### 错误做法

不要让客户端后端代打：

```text
POST http://localhost:8080/logout
```

原因：

- 这是 IdP 自己的浏览器会话接口
- 需要 `idp_csrf_token` cookie 和提交值匹配
- 这个接口不是给 RP 后端跨站代调的

### 正确做法

让浏览器直接导航到：

```text
GET http://localhost:8080/connect/logout?client_id=web-client&post_logout_redirect_uri=http://localhost:8081/&state=<random>
```

流程：

1. 浏览器进入 `GET /connect/logout`
2. IdP 在自己的站点上下文里准备 CSRF
3. 页面自动提交 `POST /connect/logout`
4. IdP 清理 `idp_session`
5. IdP `302` 回 `post_logout_redirect_uri`
6. 如果传了 `state`，会原样附加到回跳 URL

结果示例：

```text
302 http://localhost:8081/?state=<random>
```

约束：

- `post_logout_redirect_uri` 必须是预注册白名单
- 当前实现要求 `client_id` 与 `post_logout_redirect_uri` 成对提供
- 不支持 `#fragment`

## Introspection 的使用边界

当前项目已经有：

```text
POST /oauth2/introspect
```

适用场景：

- 资源服务不想自己验 JWT
- 你希望由 IdP 集中回答 token 是否仍有效

不适用场景：

- 浏览器客户端直接调用
- 前端把 access token 发给 introspection endpoint

这是资源服务到 IdP 的服务端调用。

## Discovery 里现在能拿到的关键字段

```text
GET /.well-known/openid-configuration
```

重点看：

- `authorization_endpoint`
- `token_endpoint`
- `userinfo_endpoint`
- `introspection_endpoint`
- `end_session_endpoint`
- `jwks_uri`

## 本地客户端实现建议

### Web 客户端

- 本地 session 和 IdP session 分开管理
- 本地未登录时，只做重定向，不做本地登录表单
- callback 成功后再建立自己的 session
- logout 时先清自己本地 session，再让浏览器导航去 `end_session_endpoint`

### 桌面客户端

推荐两种回调模式：

1. Loopback 回调
   - 例如 `http://127.0.0.1:8787/callback`
   - 最稳，调试简单
2. Custom scheme
   - 例如 `myapp://callback`
   - 需要操作系统侧 URI scheme 注册

当前项目对这两种 URI 都能接受，只要预注册且不带 fragment。

## 当前实现的硬约束

- `redirect_uri` 严格匹配白名单
- `post_logout_redirect_uri` 严格匹配白名单
- authorize 阶段只预检查 PKCE，真正校验在 token 阶段
- `return_to` 只用于 IdP 自己页面内部跳转，不是给客户端跨站回跳用的
- `/logout` 仍然是 IdP 本地浏览器接口；RP 应走 `/connect/logout`

## 最小排障清单

### 回调拿到 `error=invalid_request`

先查：

- `redirect_uri` 是否注册
- `client_id` 是否正确
- `scope` 是否在 client 白名单里
- `code_challenge_method` 是否是 `plain` 或 `S256`

### 看不到 IdP 登录页

先查：

- authorize 请求是否在参数校验阶段就失败
- `redirect_uri` 是否和白名单逐字相等

### 登出后又被秒登回去

先查：

- 你是否只清了本地 session，没走 `end_session_endpoint`
- `post_logout_redirect_uri` 是否注册
- 浏览器是否真的完成了 `/connect/logout` -> `POST /connect/logout` 这段流程
