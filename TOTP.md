# 本地客户端接入 TOTP 实装说明

本文面向“已有本地客户端（Web/桌面/CLI）”，按当前服务端代码实际行为整理。

## 0. `login_totp.html` 这个页面是怎么给出的

页面不是静态文件直出，而是 Go 模板渲染链路：

1. 模板编译进二进制：`idp-server/resource/templates.go`
   1. `//go:embed static/*.html`
   2. `LoginTOTPTemplate = template.ParseFS(..., "static/login_totp.html")`
2. 路由绑定：`idp-server/internal/interfaces/http/router.go`
   1. `GET /login/totp`
   2. `POST /login/totp`
   3. 都走 `LoginTOTPHandler.Handle`
3. GET 阶段渲染：`idp-server/internal/interfaces/http/handler/login_totp_handler.go`
   1. `GET /login/totp` -> `h.render(...)`
   2. `render()` 先补 `csrf_token`
   3. 当 `Accept` 偏向 HTML 时，执行 `resource.LoginTOTPTemplate.Execute(...)`，返回的就是 `login_totp.html`
   4. 当 `Accept: application/json` 时，不渲染 HTML，只返回 JSON（`csrf_token` + `error`）

结论：

- 浏览器常规访问 `/login/totp` 会看到模板页面。
- API 客户端显式 `Accept: application/json` 时拿到的是 JSON，不是 HTML。

## 1. 协议固定事实（必须按这个做）

1. TOTP 参数固定：`SHA1`、`6` 位、`30s` 步长、允许时间偏差 `±1` 个步长（约 `±30s`）。
2. 登录二阶段挑战依赖 cookie：`idp_mfa_challenge`（默认 5 分钟）。
3. 登录成功后的会话 cookie：`idp_session`。
4. CSRF 使用双提交：请求体 `csrf_token`（或头 `X-CSRF-Token`）必须等于 cookie `idp_csrf_token`。
5. 若你要稳定拿 JSON，所有请求都显式带 `Accept: application/json`。否则服务端可能返回 HTML 页面。
6. 当前默认开启强制绑定策略：`FORCE_MFA_ENROLLMENT=true`。未绑定 TOTP 的密码登录不会直接放行到业务回调，而是先跳到绑定页。

## 2. 客户端必须具备的最小能力

1. 维护 cookie jar（至少：`idp_csrf_token`、`idp_mfa_challenge`、`idp_session`）。
2. 每次进入表单类 POST 前，先 GET 对应页面拿最新 `csrf_token`。
3. 统一错误分流：`400` 参数问题、`401` 凭证/TOTP 挑战问题、`403` CSRF、`409` 已启用。
4. 登录与绑定流程分离：
   1. 绑定流程：`/mfa/totp/setup`（要求已登录）。
   2. 登录二阶段：`/login` -> `mfa_required` -> `/login/totp`。

## 3. 流程 A：已登录用户绑定 TOTP

### A1. 拉起绑定

1. `GET /mfa/totp/setup`（带 `idp_session` cookie）。
2. 成功 `200` 返回：
   1. `secret`
   2. `provisioning_uri`（`otpauth://totp/...`）
   3. `qr_code_url`
   4. `csrf_token`
   5. `already_enabled`

### A2. 二维码展示

1. `qr_code_url` 现在是服务端本地生成的 `data:image/png;base64,...`（不是外链二维码服务）。
2. 也可走手输 `secret`。

### A3. 确认绑定

1. `POST /mfa/totp/setup`，提交 `{ code, csrf_token }`。
2. 成功 `200`：`enabled=true`。
3. `409`：表示该账号已经启用 TOTP，客户端应直接结束绑定页。
4. `400`：可能是 code 错或 enrollment 过期。服务端可能返回新的 `secret/provisioning_uri`，客户端必须覆盖旧数据再让用户重试。

### A4. 超时边界

1. enrollment 默认 10 分钟；超时后必须重新从 A1 开始。

## 4. 流程 B：登录时二阶段 TOTP（详细跳转版）

下面按“浏览器 HTML 流”先写，再给“JSON API 流”。

### B0. 常见入口：从授权端点被重定向到登录

1. 用户先访问：`GET /oauth2/authorize?...`
2. 若当前无有效 `idp_session`，服务端 302 到：
   1. `/login?return_to=<原始 authorize URL>`
3. 这个 `return_to` 是后续登录成功后的回跳目标。

### B1. 第一步密码登录（HTML 流）

1. 浏览器 `GET /login?return_to=...`
   1. 返回 `login.html`
   2. 同时下发/刷新 `idp_csrf_token`
2. 用户提交 `POST /login`（用户名、密码、csrf_token）
3. 若账号启用了 TOTP：
   1. 返回 `401`（服务端内部语义：`mfa required`）
   2. 下发 `idp_mfa_challenge=<challenge_id>; Max-Age=300`
   3. HTML 分支会直接 `302 -> /login/totp`
4. 若账号未启用 TOTP 且密码正确（强制策略开启时）：
   1. 下发临时登录态 `idp_session`
   2. `302 -> /mfa/totp/setup?return_to=<原始回跳目标>`
   3. 必须完成绑定后才会继续回到 `return_to`
5. 若账号未启用 TOTP 且强制策略关闭：
   1. 下发 `idp_session`
   2. `302 -> return_to`（通常回到 `/oauth2/authorize...`）

### B2. 第二步 TOTP 页面展示（HTML 流）

1. 浏览器跟随跳转 `GET /login/totp`
2. 服务端返回 `login_totp.html`（模板渲染）
3. 页面里包含新的 `csrf_token`

说明：

- `GET /login/totp` 本身不强校验 challenge，有可能“直接打开页面”。
- 真正的挑战校验发生在 `POST /login/totp`。

### B3. 提交 TOTP（HTML 流）

1. 用户 `POST /login/totp`，携带：
   1. 表单 `code`
   2. `csrf_token`
   3. cookie `idp_mfa_challenge`
2. 服务端验证成功：
   1. 清理 `idp_mfa_challenge`
   2. 下发 `idp_session`
   3. `302 -> return_to`（若有），否则走 JSON 200 分支
3. 服务端验证失败：
   1. `401 invalid totp code`：仍留在 TOTP 页重试
   2. `401 mfa challenge expired`：清理 `idp_mfa_challenge`，需要回到 `/login` 重新做密码阶段

### B4. JSON API 流（无浏览器自动跳转）

1. `GET /login` -> 拿 `csrf_token`
2. `POST /login`
   1. 若返回 `401` 且 `mfa_required=true`，保存 cookie `idp_mfa_challenge`
3. `GET /login/totp` -> 拿二阶段 `csrf_token`
4. `POST /login/totp`
   1. 成功 `200`，返回会话信息，并下发 `idp_session`
   2. 失败 `401`（invalid code 或 challenge expired）

### B5. Cookie 与状态变化（登录路径）

1. `/login` 阶段：创建或刷新 `idp_csrf_token`
2. 密码通过且需 MFA：设置 `idp_mfa_challenge`（5 分钟）
3. `/login/totp` 成功：删除 `idp_mfa_challenge`，设置 `idp_session`
4. `/login/totp` challenge 过期：删除 `idp_mfa_challenge`

## 5. 状态机（客户端视角）

1. `ANON` -> `LOGIN_PASSWORD_SUBMIT`
2. `LOGIN_PASSWORD_SUBMIT` -> `AUTHENTICATED`（无 MFA）
3. `LOGIN_PASSWORD_SUBMIT` -> `MFA_CHALLENGE_PENDING`（401 + `mfa_required=true`）
4. `MFA_CHALLENGE_PENDING` -> `MFA_VERIFY_SUBMIT`
5. `MFA_VERIFY_SUBMIT` -> `AUTHENTICATED`（`idp_session` 下发）
6. `MFA_VERIFY_SUBMIT` -> `MFA_CHALLENGE_PENDING`（code 错）
7. `MFA_VERIFY_SUBMIT` -> `LOGIN_PASSWORD_SUBMIT`（challenge 过期）

绑定分支：

1. `AUTHENTICATED` -> `TOTP_ENROLLMENT_PENDING`
2. `TOTP_ENROLLMENT_PENDING` -> `TOTP_ENABLED`
3. `TOTP_ENROLLMENT_PENDING` -> `TOTP_ENROLLMENT_PENDING`（code 错，可能刷新 secret）
4. `TOTP_ENROLLMENT_PENDING` -> `AUTHENTICATED`（已启用 `409`）

## 6. 推荐的本地数据结构

```text
AuthContext {
  cookies: CookieJar
  csrfToken: string
  loginChallengeId: string
  totpEnrollment: {
    secret: string
    provisioningUri: string
    qrCodeUrl: string
    issuedAt: unix_ms
  }
}
```

要点：

1. `loginChallengeId` 只用于诊断，真正校验依赖 cookie。
2. `totpEnrollment` 需要可覆盖更新，避免过期 secret 反复重试。

## 7. 最小实现伪代码（语言无关）

```text
function getJson(path):
  return http.get(path, headers={"Accept":"application/json"}, withCookies=true)

function postJson(path, body):
  return http.post(path, headers={"Accept":"application/json"}, json=body, withCookies=true)

function loginWithPassword(username, password, returnTo):
  info = getJson("/login?return_to=" + urlEncode(returnTo))
  r = postJson("/login", {username, password, return_to: returnTo, csrf_token: info.csrf_token})
  if r.status == 200: return AUTH_OK
  if r.status == 401 and r.body.mfa_required == true:
    return MFA_REQUIRED
  return AUTH_FAIL

function verifyLoginTotp(code):
  info = getJson("/login/totp")
  r = postJson("/login/totp", {code, csrf_token: info.csrf_token})
  if r.status in [200,302]: return AUTH_OK
  if r.status == 401 and contains(r.body.error, "expired"): return CHALLENGE_EXPIRED
  if r.status == 401: return CODE_INVALID
  return AUTH_FAIL

function beginTotpSetup():
  r = getJson("/mfa/totp/setup")
  if r.status == 200: return r.body
  if r.status == 302: return NEED_LOGIN
  return FAIL

function confirmTotpSetup(code, csrfToken):
  r = postJson("/mfa/totp/setup", {code, csrf_token: csrfToken})
  if r.status == 200 and r.body.enabled == true: return ENABLED
  if r.status == 409: return ALREADY_ENABLED
  if r.status == 400: return RETRY_WITH_LATEST_PAYLOAD(r.body)
  return FAIL
```

## 8. 联调检查清单

1. 每个 POST 前是否重新拿过 `csrf_token`。
2. 请求是否始终携带 cookie jar。
3. `Accept` 是否固定 `application/json`。
4. 是否正确处理 `401 + mfa_required` 与普通 `401` 的分流。
5. challenge 过期后是否强制回到密码阶段。
6. 设备时间是否同步（NTP），否则 TOTP 误判率会高。

## 9. 参考契约与代码入口

1. `idp-server/api/openapi.yaml`
2. `GET/POST /login`
3. `GET/POST /login/totp`
4. `GET/POST /mfa/totp/setup`
5. 模板入口：`idp-server/resource/templates.go`
6. 路由入口：`idp-server/internal/interfaces/http/router.go`
7. Handler：
   1. `idp-server/internal/interfaces/http/handler/login_handler.go`
   2. `idp-server/internal/interfaces/http/handler/login_totp_handler.go`
