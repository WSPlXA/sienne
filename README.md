# oauth2-sienne-idp

Language: [English](README.md) | [简体中文](README.zh-CN.md)

`oauth2-sienne-idp` is a Go-based Identity Provider (IdP) that implements OAuth2 + OpenID Connect with production-oriented controls for session state, token lifecycle, replay protection, and key rotation.

This README is rebuilt from the current project docs:
- [interview_.md](interview_.md)
- [idp-server/detail.md](idp-server/detail.md)
- [idp-server/sequence.md](idp-server/sequence.md)

## What Is Implemented

### Authentication and Session
- Local registration, login, logout
- Browser session cookie (`idp_session`) backed by MySQL + Redis
- Federated OIDC login (upstream OP -> local user mapping with first-login auto-provisioning)
- OIDC end-session endpoint (`/connect/logout`)
- Logout current session and logout all sessions for current user

### OAuth2 / OIDC
- `authorization_code` + PKCE (`plain` and `S256`)
- Consent screen and consent reuse
- Refresh token rotation
- `client_credentials`
- `password` (legacy grant)
- `urn:ietf:params:oauth:grant-type:device_code`
- Discovery, UserInfo, Introspection, JWKS

### MFA
- TOTP enrollment (QR returned as data URL)
- TOTP login challenge (`/login/totp`)
- Forced MFA enrollment policy (`FORCE_MFA_ENROLLMENT=true` by default)
- TOTP step replay protection (`user + purpose + step`)

### Security and Operations
- CSRF double-submit protection (cookie + body/header)
- `return_to` local-path validation (open redirect guard)
- Login rate limiting and account lock
- **High-Performance State Machine**: Session and MFA states use 32-bit bitmasks instead of string comparisons, leveraging CPU-native bitwise operations for state validation.
- **Atomic CAS (Compare-And-Swap)**: Redis-native optimistic concurrency control via Lua scripts prevents "lost updates" and ensures atomic state transitions in concurrent flows.
- **Hardware-Friendly Cache Layer**: Optimized Redis access using `HMGet` and packed `BITFIELD` state storage, reducing memory allocations and network RTT.
- Redis Lua scripts for atomic state changes
- 32-bit RBAC privilege mask for admin endpoints
- Audit trail in `audit_events` for admin-sensitive operations
- Built-in operator role bootstrap and role assignment APIs

## Architecture Summary

The deployment model is stateless application instances with shared state services:
- MySQL stores durable entities (users, clients, auth codes, tokens, sessions, key metadata, audits).
- Redis stores hot/ephemeral state (session cache, state/nonce, replay locks, throttle counters, MFA challenges, device flow state).
- JWT + JWKS allows resource services to validate access tokens locally when needed.

This gives horizontal scalability without depending on in-memory session state in a single node.

## Repository Structure

- `idp-server/cmd/idp`: app entrypoint
- `idp-server/internal/application`: core business orchestration
- `idp-server/internal/interfaces/http`: HTTP handlers/router
- `idp-server/internal/infrastructure`: MySQL/Redis/crypto/external integrations
- `idp-server/internal/plugins`: pluggable authn/client-auth/grant handlers
- `idp-server/scripts/migrate.sql`: schema + seed fixtures
- `idp-server/scripts/lua`: Redis atomic scripts
- `idp-server/deploy`: k8s/podman deployment manifests

## Quick Start

### Option A: Prebuilt Image Stack (repo root)

```bash
docker compose -f compose.quickstart.yaml up -d
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/.well-known/openid-configuration
```

### Option B: Build Locally from Source

```bash
cd idp-server
docker compose up -d --build
curl -sS http://localhost:8080/healthz
```

### Run Tests

```bash
cd idp-server
go test ./...
```

## Seed Data (for Local Demo)

Source: `idp-server/scripts/migrate.sql`

### Users
- `alice / alice123`
- `bob / bob123`
- `locked_user / locked123` (locked by default)

### Clients
- `web-client` (`authorization_code`, `refresh_token`, PKCE required)
- `mobile-public-client` (`authorization_code`, `refresh_token`, public client, auth method `none`)
- `service-client` (`client_credentials`)
- `legacy-client` (`password`, `refresh_token`)
- `tv-client` (`urn:ietf:params:oauth:grant-type:device_code`)

Fixture plaintext secrets are generated in `idp-server/scripts/generate_fixture_hashes.go`:
- `web-client`: `secret123`
- `service-client`: `service123`

`legacy-client` and `tv-client` share the same seeded secret hash as `service-client` in `migrate.sql`.

### Seeded Flow Fixtures
- session id: `aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`
- authorization code: `sample_auth_code_abc123`
- PKCE verifier fixture: `verifier123`
- seed redirect URI: `http://localhost:3060/callback`

## Endpoint Overview

Router source: `idp-server/internal/interfaces/http/router.go`

### UI/Auth
- `/register`, `/login`, `/login/totp`, `/mfa/totp/setup`, `/consent`, `/device`
- `/logout`, `/logout/all`, `/connect/logout`

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

## Key Configuration

Config bootstrap source: `idp-server/internal/bootstrap/wire.go`

### Core Runtime
- `ISSUER` (default `http://localhost:8080`)
- `TOTP_ISSUER` (optional display name in authenticator apps; fallback is host from `ISSUER`)
- `LISTEN_ADDR` (default `:8080`)
- `SESSION_TTL` (default `8h`)
- `APP_ENV` (default `dev`)

### Storage
- `MYSQL_DSN` (full DSN, highest priority) or `MYSQL_HOST`/`MYSQL_PORT`/...
- `REDIS_ADDR` (full address, highest priority) or `REDIS_HOST`/`REDIS_PORT`/...
- `REDIS_KEY_PREFIX` (default `idp`)

### Security Controls
- `FORCE_MFA_ENROLLMENT` (default `true`)
- `LOGIN_FAILURE_WINDOW`
- `LOGIN_MAX_FAILURES_PER_IP`
- `LOGIN_MAX_FAILURES_PER_USER`
- `LOGIN_USER_LOCK_THRESHOLD`
- `LOGIN_USER_LOCK_TTL`

### JWT and Key Rotation
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
- `FEDERATED_OIDC_PROVIDER_NAME` (login button label, default `OpenID Connect`)
- `FEDERATED_OIDC_CLIENT_AUTH_METHOD`
- `FEDERATED_OIDC_SCOPES`
- `FEDERATED_OIDC_STATE_TTL`

### Google Federated Login (Quick Start)
1. Create an OAuth Client (Web Application) in Google Cloud Console and set callback URL to `http://localhost:8080/login` for local development.
2. Set:
   - `FEDERATED_OIDC_ISSUER=https://accounts.google.com`
   - `FEDERATED_OIDC_CLIENT_ID=<your-client-id>`
   - `FEDERATED_OIDC_CLIENT_SECRET=<your-client-secret>`
   - `FEDERATED_OIDC_REDIRECT_URI=http://localhost:8080/login`
3. Recommended extras:
   - `FEDERATED_OIDC_PROVIDER_NAME=Google`
   - `FEDERATED_OIDC_CLIENT_AUTH_METHOD=client_secret_post`
   - `FEDERATED_OIDC_USERNAME_CLAIM=email`
4. Restart `idp-server` and open `/login`; the federated button shows Google and follows the upstream callback flow.

## Deep-Dive Docs

- System walkthrough: [idp-server/detail.md](idp-server/detail.md)
- Interview-oriented narrative: [interview_.md](interview_.md)
- Sequence diagrams: [idp-server/sequence.md](idp-server/sequence.md)
- Deployment notes (Kubernetes/Podman): [idp-server/deploy/README.md](idp-server/deploy/README.md)

## Deployment Note for Key Rotation

Current key management persists key metadata in DB and references private keys by filesystem path.  
For safe multi-replica signing, move private-key storage to shared KMS/Vault/RWX storage with explicit leader control before scaling `idp-server` writers.
