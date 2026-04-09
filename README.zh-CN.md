# oauth2-sienne-idp

语言: [English](README.md) | [简体中文](README.zh-CN.md)

`oauth2-sienne-idp` 是一个基于 Go 的 Identity Provider（IdP），实现 OAuth2 + OpenID Connect，并提供面向生产的会话状态、令牌生命周期、防重放与签名密钥轮转能力。

本文档基于当前项目资料重建：
- [interview_.md](interview_.md)
- [idp-server/detail.md](idp-server/detail.md)
- [idp-server/sequence.md](idp-server/sequence.md)

## 已实现能力

### 认证与会话
- 本地注册、登录、登出
- 浏览器会话 Cookie（`idp_session`）由 MySQL + Redis 联合承载
- Federated OIDC 登录（上游 OP 回调后映射本地用户）
- OIDC End Session（`/connect/logout`）
- 当前会话登出与当前用户全端下线

### OAuth2 / OIDC
- `authorization_code` + PKCE（`plain` / `S256`）
- Consent 页面与同意记录复用
- Refresh Token Rotation
- `client_credentials`
- `password`（legacy grant）
- `urn:ietf:params:oauth:grant-type:device_code`
- Discovery、UserInfo、Introspection、JWKS

### MFA
- TOTP 绑定（二维码以 data URL 返回）
- TOTP 二步验证（`/login/totp`）
- 强制 MFA 入组策略（默认 `FORCE_MFA_ENROLLMENT=true`）
- TOTP step 防重放（`user + purpose + step`）

### 安全与运维
- CSRF 双提交校验（cookie + body/header）
- `return_to` 本地路径校验（防开放重定向）
- 登录失败限流与用户锁定
- Redis Lua 脚本保证状态更新原子性
- 32 位 RBAC 权限掩码保护管理接口
- 管理关键操作写入 `audit_events` 审计日志
- 内置角色初始化与用户角色分配接口

## 架构摘要

部署模型为应用实例尽量无状态，状态由共享存储承载：
- MySQL：持久化实体（用户、客户端、授权码、令牌、会话、密钥元数据、审计日志）
- Redis：热/临时状态（session cache、state/nonce、防重放、限流计数、MFA challenge、device flow 状态）
- JWT + JWKS：资源服务可按需本地验签 access token

这让系统可以横向扩展，而不依赖单机内存会话。

## 目录结构

- `idp-server/cmd/idp`: 程序入口
- `idp-server/internal/application`: 核心业务编排
- `idp-server/internal/interfaces/http`: HTTP 处理与路由
- `idp-server/internal/infrastructure`: MySQL/Redis/crypto/外部集成
- `idp-server/internal/plugins`: 可扩展 authn/client-auth/grant 处理器
- `idp-server/scripts/migrate.sql`: 数据库 schema 与 seed
- `idp-server/scripts/lua`: Redis 原子脚本
- `idp-server/deploy`: k8s/podman 部署清单

## 快速开始

### 方案 A：使用预构建镜像（仓库根目录）

```bash
docker compose -f compose.quickstart.yaml up -d
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/.well-known/openid-configuration
```

### 方案 B：本地源码构建

```bash
cd idp-server
docker compose up -d --build
curl -sS http://localhost:8080/healthz
```

### 运行测试

```bash
cd idp-server
go test ./...
```

## Seed 数据（本地演示）

来源：`idp-server/scripts/migrate.sql`

### 用户
- `alice / alice123`
- `bob / bob123`
- `locked_user / locked123`（默认 locked）

### 客户端
- `web-client`（`authorization_code`、`refresh_token`、强制 PKCE）
- `mobile-public-client`（`authorization_code`、`refresh_token`、public client、`none` 认证方式）
- `service-client`（`client_credentials`）
- `legacy-client`（`password`、`refresh_token`）
- `tv-client`（`urn:ietf:params:oauth:grant-type:device_code`）

明文 fixture secret 定义在 `idp-server/scripts/generate_fixture_hashes.go`：
- `web-client`: `secret123`
- `service-client`: `service123`

`legacy-client` 与 `tv-client` 在 `migrate.sql` 中复用了与 `service-client` 相同的 seed secret hash。

### 预置流程样本
- session id: `aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`
- authorization code: `sample_auth_code_abc123`
- PKCE verifier 样本: `verifier123`
- seed redirect URI: `http://localhost:3060/callback`

## 端点总览

路由定义：`idp-server/internal/interfaces/http/router.go`

### UI/Auth
- `/register`、`/login`、`/login/totp`、`/mfa/totp/setup`、`/consent`、`/device`
- `/logout`、`/logout/all`、`/connect/logout`

### OAuth2/OIDC
- `/.well-known/openid-configuration`
- `/oauth2/authorize`
- `/oauth2/token`
- `/oauth2/device/authorize`
- `/oauth2/introspect`
- `/oauth2/userinfo`
- `/oauth2/jwks`

### Admin/RBAC
- `/admin/rbac/roles`
- `/admin/rbac/roles/:role_code/users`
- `/admin/rbac/usage`
- `/admin/rbac/bootstrap`
- `/admin/rbac/roles`
- `/admin/users/:user_id/role`
- `/admin/users/:user_id/logout-all`

## 核心配置

配置装配入口：`idp-server/internal/bootstrap/wire.go`

### 运行时
- `ISSUER`（默认 `http://localhost:8080`）
- `TOTP_ISSUER`（可选，认证器中显示名称；未设置时自动回退为 `ISSUER` 的域名）
- `LISTEN_ADDR`（默认 `:8080`）
- `SESSION_TTL`（默认 `8h`）
- `APP_ENV`（默认 `dev`）

### 存储
- `MYSQL_DSN`（完整 DSN，优先级最高）或 `MYSQL_HOST`/`MYSQL_PORT`/...
- `REDIS_ADDR`（完整地址，优先级最高）或 `REDIS_HOST`/`REDIS_PORT`/...
- `REDIS_KEY_PREFIX`（默认 `idp`）

### 安全控制
- `FORCE_MFA_ENROLLMENT`（默认 `true`）
- `LOGIN_FAILURE_WINDOW`
- `LOGIN_MAX_FAILURES_PER_IP`
- `LOGIN_MAX_FAILURES_PER_USER`
- `LOGIN_USER_LOCK_THRESHOLD`
- `LOGIN_USER_LOCK_TTL`

### JWT 与密钥轮转
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
- `FEDERATED_OIDC_SCOPES`
- `FEDERATED_OIDC_STATE_TTL`

## 深入文档

- 系统详解: [idp-server/detail.md](idp-server/detail.md)
- 面试表述版: [interview_.md](interview_.md)
- 时序图: [idp-server/sequence.md](idp-server/sequence.md)
- 部署说明（Kubernetes/Podman）: [idp-server/deploy/README.md](idp-server/deploy/README.md)

## 密钥轮转部署注意事项

当前密钥管理是数据库保存元数据 + 文件路径引用私钥。  
如果要安全扩展到多副本写入，请先把私钥迁移到共享 KMS/Vault/RWX 存储，并增加明确的单写控制（leader 机制）后再扩容签发节点。
