# oauth2-sienne-idp

一个用 Go 实现的 IDP / OAuth2 / OIDC 服务仓库。当前代码已经能跑通本地账号登录、Authorization Code + PKCE、Consent、Refresh Token Rotation、`client_credentials`、`userinfo`、Discovery、JWKS，以及基于 Redis Lua 的状态控制。

根目录主要放“快速拉起”资产，真正的服务源码在 [`idp-server/`](./idp-server)。

## 当前能力

- 本地账号注册、登录、登出
- OAuth2 Authorization Code Flow，支持 PKCE
- Consent 页面与已授权 scope 复用
- `refresh_token` 轮转
- `client_credentials`
- OIDC `userinfo`、`/.well-known/openid-configuration`、`/oauth2/jwks`
- `/oauth2/introspect`
- Redis Lua 脚本预加载，用于 session、state/nonce、防重放、token revoke/rotate
- 签名密钥持久化与单进程轮转
- Federated OIDC 登录入口，当前要求本地用户已存在

## 仓库结构

| 路径 | 作用 |
| --- | --- |
| [`README.md`](./README.md) | 仓库入口文档 |
| [`compose.quickstart.yaml`](./compose.quickstart.yaml) | 用预构建镜像快速启动 MySQL、Redis、server |
| [`quickstart.ps1`](./quickstart.ps1) | Windows 一键启动脚本 |
| [`idp-server/`](./idp-server) | Go 服务源码、Dockerfile、Makefile、SQL、Lua 脚本 |
| [`idp-server/api/openapi.yaml`](./idp-server/api/openapi.yaml) | 主要 HTTP 接口契约，最新路由仍以代码为准 |
| [`idp-server/scripts/migrate.sql`](./idp-server/scripts/migrate.sql) | MySQL schema 和 seed 数据 |
| [`idp-server/scripts/lua/README.md`](./idp-server/scripts/lua/README.md) | Redis Lua 脚本说明 |

## 快速启动

### 方式一：直接跑预构建镜像

适合先验证接口，不改源码。

```bash
docker compose -f compose.quickstart.yaml up -d
curl http://localhost:8080/healthz
```

预期返回：

```json
{"status":"ok"}
```

如果拉取 `ghcr.io/wsplxa/oauth2-sienne-idp-server` 失败，先登录 GHCR：

```bash
echo "$GHCR_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USERNAME --password-stdin
```

Windows 也可以直接跑脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\quickstart.ps1
```

停止：

```bash
docker compose -f compose.quickstart.yaml down
```

连卷一起清掉：

```bash
docker compose -f compose.quickstart.yaml down -v
```

### 方式二：源码开发

适合本地改 Go 代码。

前提：

- Go 1.24+
- Docker Compose v2
- GNU Make
- `bash`

注意：[`idp-server/Makefile`](./idp-server/Makefile) 把 `SHELL` 固定成了 `/bin/bash`。在 Windows 上请用 WSL、Git Bash 或 MSYS2，不要假设 PowerShell 里直接 `make` 就能跑通。

启动依赖：

```bash
cd idp-server
docker compose up -d db redis
make migrate-docker
make run
```

常用命令：

```bash
make build
make test
make fmt
make env
```

如果你想连 server 一起放进容器里运行，也可以在 [`idp-server/`](./idp-server) 下直接：

```bash
make up
make logs
make down
```

## 常用环境变量

完整配置解析见 [`idp-server/internal/bootstrap/wire.go`](./idp-server/internal/bootstrap/wire.go)。这里列真正常用的。

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `MYSQL_DSN` | 完整 MySQL DSN。设置后优先使用 | 无 |
| `MYSQL_HOST` `MYSQL_PORT` `MYSQL_DATABASE` `MYSQL_USER` `MYSQL_PASSWORD` | 未提供 `MYSQL_DSN` 时使用 | `db` `3306` `app` `app` `apppass` |
| `REDIS_ADDR` | 完整 Redis 地址。设置后优先使用 | 无 |
| `REDIS_HOST` `REDIS_PORT` `REDIS_DB` | 未提供 `REDIS_ADDR` 时使用 | `redis` `6379` `0` |
| `REDIS_PASSWORD` | Redis 密码 | 空 |
| `REDIS_KEY_PREFIX` | Redis key 前缀 | `idp` |
| `APP_ENV` | 环境名 | `dev` |
| `LISTEN_ADDR` | HTTP 监听地址 | `:8080` |
| `ISSUER` | OIDC issuer | `http://localhost:8080` |
| `SESSION_TTL` | 登录 session 生命周期 | `8h` |
| `LOGIN_FAILURE_WINDOW` | 登录失败统计窗口 | `15m` |
| `LOGIN_MAX_FAILURES_PER_IP` | 单 IP 失败上限 | `20` |
| `LOGIN_MAX_FAILURES_PER_USER` | 单用户失败上限 | `5` |
| `LOGIN_USER_LOCK_THRESHOLD` | 用户锁定阈值 | `5` |
| `LOGIN_USER_LOCK_TTL` | 用户锁定时长 | `30m` |
| `JWT_KEY_ID` | JWT `kid` 回退值 | `kid-2026-01-rs256` |
| `SIGNING_KEY_DIR` | 本地签名密钥目录 | `scripts/dev_keys` |
| `SIGNING_KEY_CHECK_INTERVAL` | 轮转检查周期 | `1h` |
| `SIGNING_KEY_ROTATE_BEFORE` | 提前多久生成新 key | `24h` |
| `SIGNING_KEY_RETIRE_AFTER` | 旧 key 保留窗口 | `24h` |
| `FEDERATED_OIDC_*` | 外部 OIDC Provider 配置 | 见代码默认值 |

## Seed 数据

[`idp-server/scripts/migrate.sql`](./idp-server/scripts/migrate.sql) 会初始化以下 fixture。

### 用户

- `alice / alice123`
- `bob / bob123`
- `locked_user / locked123`

### OAuth Client

- `web-client / secret123`
- `mobile-public-client / 无 client secret`
- `service-client / service123`

### 预置会话与授权码

- `idp_session=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`
- `code=sample_auth_code_abc123`
- `redirect_uri=http://localhost:3060/callback`
- `code_verifier=verifier123`

注意：数据库里还 seed 了一条 `sample_access_token_value`，但它不是可直接拿去过 JWT 校验的真实访问令牌。要测试 `userinfo` 或 `introspect`，先用授权码换一枚真正发出来的 access token。

## API 概览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/healthz` | 健康检查 |
| `GET` `POST` | `/register` | 注册；`POST` 需要 CSRF |
| `GET` `POST` | `/login` | 登录或发起 Federated OIDC；`POST` 需要 CSRF |
| `POST` | `/logout` | 登出当前浏览器 session |
| `GET` `POST` | `/consent` | 查看/提交授权确认；`POST` 需要 CSRF |
| `GET` | `/oauth2/authorize` | Authorization Code 入口 |
| `POST` | `/oauth2/token` | `authorization_code` / `refresh_token` / `client_credentials` |
| `POST` | `/oauth2/introspect` | 访问令牌自省 |
| `GET` | `/oauth2/userinfo` | OIDC UserInfo |
| `GET` | `/.well-known/openid-configuration` | OIDC Discovery |
| `GET` | `/oauth2/jwks` | 公钥集合 |
| `POST` | `/oauth2/clients` | 创建 OAuth client |
| `POST` | `/oauth2/clients/:client_id/redirect-uris` | 追加 redirect URI |

## 调用示例

### 用 seed authorization code 换 token

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/token \
  -u web-client:secret123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'code=sample_auth_code_abc123' \
  -d 'redirect_uri=http://localhost:3060/callback' \
  -d 'code_verifier=verifier123'
```

如果请求 scope 里包含 `openid`，响应会带上 `id_token`。

### 用 refresh token 轮转

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/token \
  -u web-client:secret123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d 'refresh_token=REPLACE_WITH_REFRESH_TOKEN'
```

### 用 service client 走 `client_credentials`

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/token \
  -u service-client:service123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'scope=internal.api.read'
```

### 查询 `userinfo`

```bash
curl -i \
  http://localhost:8080/oauth2/userinfo \
  -H 'Authorization: Bearer REPLACE_WITH_ACCESS_TOKEN'
```

### 查询 token introspection

```bash
curl -i \
  -X POST http://localhost:8080/oauth2/introspect \
  -u web-client:secret123 \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'token=REPLACE_WITH_ACCESS_TOKEN'
```

## 几个容易踩坑的点

- `curl` 默认发 `Accept: */*`，而 `GET /login`、`GET /consent` 会优先回 HTML。脚本模式下请显式带 `Accept: application/json`。
- `POST /login`、`POST /register`、`POST /consent` 必须先通过对应的 `GET` 拿 `csrf_token`，并且带回 `idp_csrf_token` cookie。
- 根目录的 [`compose.quickstart.yaml`](./compose.quickstart.yaml) 走的是预构建镜像；[`idp-server/docker-compose.yml`](./idp-server/docker-compose.yml) 走的是本地构建，两者不要混着理解。
- `return_to` 只接受本地路径，不能随便塞外部 URL。

## 相关文档

- 主要接口契约：[`idp-server/api/openapi.yaml`](./idp-server/api/openapi.yaml)
- Redis Lua 说明：[`idp-server/scripts/lua/README.md`](./idp-server/scripts/lua/README.md)
- SQL schema 与 seed：[`idp-server/scripts/migrate.sql`](./idp-server/scripts/migrate.sql)
- 路由入口：[`idp-server/internal/interfaces/http/router.go`](./idp-server/internal/interfaces/http/router.go)

## 当前限制

- Federated OIDC 只做了“外部身份 -> 本地已有用户”映射，未做首次登录自动建号。
- 签名密钥轮转是单进程定时器模型，还没有分布式锁或独立控制面。
- 接口文档和路由在持续演进，最终以代码为准。
