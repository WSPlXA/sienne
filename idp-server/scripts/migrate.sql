-- =========================================================
-- Go IdP / OAuth2 / OIDC - MySQL 8.0 Migration
-- File: migrate.sql
-- Charset: utf8mb4
-- Engine: InnoDB
-- =========================================================

SET NAMES utf8mb4;

SET FOREIGN_KEY_CHECKS = 0;

-- =========================================================
-- Drop old tables (reverse dependency order)
-- =========================================================
DROP TABLE IF EXISTS audit_events;

DROP TABLE IF EXISTS jwk_keys;

DROP TABLE IF EXISTS oauth_refresh_tokens;

DROP TABLE IF EXISTS oauth_access_tokens;

DROP TABLE IF EXISTS oauth_consents;

DROP TABLE IF EXISTS oauth_authorization_codes;

DROP TABLE IF EXISTS login_sessions;

DROP TABLE IF EXISTS oauth_client_scopes;

DROP TABLE IF EXISTS oauth_client_auth_methods;

DROP TABLE IF EXISTS oauth_client_grant_types;

DROP TABLE IF EXISTS oauth_client_redirect_uris;

DROP TABLE IF EXISTS oauth_client_post_logout_redirect_uris;

DROP TABLE IF EXISTS oauth_clients;

DROP TABLE IF EXISTS users;

SET FOREIGN_KEY_CHECKS = 1;

-- =========================================================
-- 1. Users
-- =========================================================
CREATE TABLE users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT COMMENT 'internal user id',
    user_uuid CHAR(36) NOT NULL COMMENT 'external stable user uuid',
    username VARCHAR(64) NOT NULL,
    email VARCHAR(255) NOT NULL,
    email_verified TINYINT(1) NOT NULL DEFAULT 0,
    display_name VARCHAR(128) NOT NULL,
    password_hash VARCHAR(255) NOT NULL COMMENT 'bcrypt/argon2 hash',
    status VARCHAR(32) NOT NULL DEFAULT 'active' COMMENT 'active/locked/disabled',
    failed_login_count INT NOT NULL DEFAULT 0,
    last_login_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_users_user_uuid (user_uuid),
    UNIQUE KEY uk_users_username (username),
    UNIQUE KEY uk_users_email (email),
    KEY idx_users_status (status)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'end users';

-- =========================================================
-- 2. Login sessions
-- =========================================================
CREATE TABLE login_sessions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_id CHAR(36) NOT NULL COMMENT 'browser/session cookie id',
    user_id BIGINT UNSIGNED NOT NULL,
    subject VARCHAR(128) NOT NULL COMMENT 'OIDC subject',
    acr VARCHAR(128) NULL,
    amr_json JSON NULL COMMENT '["pwd","otp"]',
    ip_address VARCHAR(64) NULL,
    user_agent VARCHAR(512) NULL,
    authenticated_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    logged_out_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_login_sessions_session_id (session_id),
    KEY idx_login_sessions_user_id (user_id),
    KEY idx_login_sessions_expires_at (expires_at),
    CONSTRAINT fk_login_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'browser login sessions';

-- =========================================================
-- 3. OAuth clients
-- =========================================================
CREATE TABLE oauth_clients (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    client_id VARCHAR(128) NOT NULL,
    client_name VARCHAR(128) NOT NULL,
    client_secret_hash VARCHAR(255) NULL COMMENT 'public client can be null',
    client_type VARCHAR(32) NOT NULL DEFAULT 'confidential' COMMENT 'confidential/public',
    token_endpoint_auth_method VARCHAR(64) NOT NULL DEFAULT 'client_secret_basic',
    require_pkce TINYINT(1) NOT NULL DEFAULT 1,
    require_consent TINYINT(1) NOT NULL DEFAULT 1,
    access_token_ttl_seconds INT NOT NULL DEFAULT 3600,
    refresh_token_ttl_seconds INT NOT NULL DEFAULT 2592000,
    id_token_ttl_seconds INT NOT NULL DEFAULT 3600,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_oauth_clients_client_id (client_id),
    KEY idx_oauth_clients_status (status)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'oauth2/oidc clients';

-- =========================================================
-- 4. Client redirect URIs
-- =========================================================
CREATE TABLE oauth_client_redirect_uris (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    client_id BIGINT UNSIGNED NOT NULL,
    redirect_uri VARCHAR(1024) NOT NULL,
    redirect_uri_sha256 CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_client_redirect_uri_hash (
        client_id,
        redirect_uri_sha256
    ),
    CONSTRAINT fk_client_redirect_uris_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- =========================================================
-- 5. Client grant types
-- =========================================================
CREATE TABLE oauth_client_post_logout_redirect_uris (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    client_id BIGINT UNSIGNED NOT NULL,
    redirect_uri VARCHAR(1024) NOT NULL,
    redirect_uri_sha256 CHAR(64) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_client_post_logout_redirect_uri_hash (
        client_id,
        redirect_uri_sha256
    ),
    CONSTRAINT fk_client_post_logout_redirect_uris_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci;

-- =========================================================
-- 5. Client grant types
-- =========================================================
CREATE TABLE oauth_client_grant_types (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    client_id BIGINT UNSIGNED NOT NULL,
    grant_type VARCHAR(128) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_client_grant_type (client_id, grant_type),
    KEY idx_client_grant_type (grant_type),
    CONSTRAINT fk_client_grant_types_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'allowed grant types';

-- =========================================================
-- 6. Client auth methods
-- =========================================================
CREATE TABLE oauth_client_auth_methods (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    client_id BIGINT UNSIGNED NOT NULL,
    auth_method VARCHAR(128) NOT NULL COMMENT 'client_secret_basic/private_key_jwt/etc',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_client_auth_method (client_id, auth_method),
    KEY idx_client_auth_method (auth_method),
    CONSTRAINT fk_client_auth_methods_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'allowed token endpoint auth methods';

-- =========================================================
-- 7. Client scopes
-- =========================================================
CREATE TABLE oauth_client_scopes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    client_id BIGINT UNSIGNED NOT NULL,
    scope VARCHAR(128) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_client_scope (client_id, scope),
    KEY idx_client_scope (scope),
    CONSTRAINT fk_client_scopes_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'allowed scopes for client';

-- =========================================================
-- 8. Authorization codes
-- =========================================================
CREATE TABLE oauth_authorization_codes (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    code VARCHAR(128) NOT NULL COMMENT 'raw code or securely generated opaque value',
    client_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    session_id BIGINT UNSIGNED NULL,
    redirect_uri VARCHAR(1024) NOT NULL,
    scopes_json JSON NOT NULL,
    state_value VARCHAR(512) NULL,
    nonce_value VARCHAR(512) NULL,
    code_challenge VARCHAR(255) NULL,
    code_challenge_method VARCHAR(16) NULL COMMENT 'plain/S256',
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_auth_codes_code (code),
    KEY idx_auth_codes_client_id (client_id),
    KEY idx_auth_codes_user_id (user_id),
    KEY idx_auth_codes_expires_at (expires_at),
    KEY idx_auth_codes_consumed_at (consumed_at),
    CONSTRAINT fk_auth_codes_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
    CONSTRAINT fk_auth_codes_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_auth_codes_session FOREIGN KEY (session_id) REFERENCES login_sessions (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'authorization code with pkce/nonce';

-- =========================================================
-- 9. User consent
-- =========================================================
CREATE TABLE oauth_consents (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    client_id BIGINT UNSIGNED NOT NULL,
    scopes_json JSON NOT NULL,
    granted_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_consent_user_client (user_id, client_id),
    KEY idx_consent_revoked_at (revoked_at),
    CONSTRAINT fk_consents_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_consents_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'remembered user consent';

-- =========================================================
-- 10. Access tokens
-- =========================================================
CREATE TABLE oauth_access_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_value VARCHAR(2048) NOT NULL COMMENT 'jwt or opaque token value',
    token_sha256 CHAR(64) NOT NULL COMMENT 'for secure lookup/revocation',
    client_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NULL,
    subject VARCHAR(128) NOT NULL,
    audience_json JSON NULL,
    scopes_json JSON NOT NULL,
    token_type VARCHAR(32) NOT NULL DEFAULT 'Bearer',
    token_format VARCHAR(32) NOT NULL DEFAULT 'jwt' COMMENT 'jwt/opaque',
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_access_tokens_sha256 (token_sha256),
    KEY idx_access_tokens_client_id (client_id),
    KEY idx_access_tokens_user_id (user_id),
    KEY idx_access_tokens_subject (subject),
    KEY idx_access_tokens_expires_at (expires_at),
    KEY idx_access_tokens_revoked_at (revoked_at),
    CONSTRAINT fk_access_tokens_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
    CONSTRAINT fk_access_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'issued access tokens';

-- =========================================================
-- 11. Refresh tokens
-- =========================================================
CREATE TABLE oauth_refresh_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_value VARCHAR(1024) NOT NULL COMMENT 'opaque refresh token',
    token_sha256 CHAR(64) NOT NULL,
    client_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NULL,
    subject VARCHAR(128) NOT NULL,
    scopes_json JSON NOT NULL,
    issued_at DATETIME NOT NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    replaced_by_token_id BIGINT UNSIGNED NULL COMMENT 'rotation chain',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uk_refresh_tokens_sha256 (token_sha256),
    KEY idx_refresh_tokens_client_id (client_id),
    KEY idx_refresh_tokens_user_id (user_id),
    KEY idx_refresh_tokens_subject (subject),
    KEY idx_refresh_tokens_expires_at (expires_at),
    KEY idx_refresh_tokens_revoked_at (revoked_at),
    KEY idx_refresh_tokens_replaced_by (replaced_by_token_id),
    CONSTRAINT fk_refresh_tokens_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_refresh_tokens_replaced_by FOREIGN KEY (replaced_by_token_id) REFERENCES oauth_refresh_tokens (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'issued refresh tokens';

-- =========================================================
-- 12. JWK signing keys metadata
-- =========================================================
CREATE TABLE jwk_keys (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    kid VARCHAR(128) NOT NULL,
    kty VARCHAR(32) NOT NULL,
    alg VARCHAR(32) NOT NULL,
    use_type VARCHAR(16) NOT NULL DEFAULT 'sig',
    public_jwk_json JSON NOT NULL,
    private_key_ref VARCHAR(255) NULL COMMENT 'vault ref / kms ref / secret path',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    rotates_at DATETIME NULL,
    deactivated_at DATETIME NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_jwk_keys_kid (kid),
    KEY idx_jwk_keys_active (is_active),
    KEY idx_jwk_keys_rotates_at (rotates_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'signing key metadata';

-- =========================================================
-- 13. Audit events
-- =========================================================
CREATE TABLE audit_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    event_type VARCHAR(128) NOT NULL,
    client_id BIGINT UNSIGNED NULL,
    user_id BIGINT UNSIGNED NULL,
    subject VARCHAR(128) NULL,
    session_id BIGINT UNSIGNED NULL,
    ip_address VARCHAR(64) NULL,
    user_agent VARCHAR(512) NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_events_event_type (event_type),
    KEY idx_audit_events_client_id (client_id),
    KEY idx_audit_events_user_id (user_id),
    KEY idx_audit_events_subject (subject),
    KEY idx_audit_events_created_at (created_at),
    CONSTRAINT fk_audit_events_client FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_events_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_audit_events_session FOREIGN KEY (session_id) REFERENCES login_sessions (id) ON DELETE SET NULL
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_0900_ai_ci COMMENT = 'security and business audit log';

-- =========================================================
-- Seed data
-- Password hashes below are placeholders.
-- Fixture hashes below are generated through scripts/generate_fixture_hashes.go,
-- which uses the app PasswordVerifier implementation.
-- =========================================================

-- Users
INSERT INTO
    users (
        user_uuid,
        username,
        email,
        email_verified,
        display_name,
        password_hash,
        status,
        failed_login_count,
        last_login_at
    )
VALUES (
        '11111111-1111-1111-1111-111111111111',
        'alice',
        'alice@example.com',
        1,
        'Alice',
        '$2a$10$/C9zg0s/Aqth0ARnL/DHMuD26eXehFR4X40aaQ1KzQPVV78y.VA7C',
        'active',
        0,
        NULL
    ),
    (
        '22222222-2222-2222-2222-222222222222',
        'bob',
        'bob@example.com',
        1,
        'Bob',
        '$2a$10$AzOHkvRQLxp6R22izS9VkeZiHDXLEucXUwS.QRuSdGPKdfOGyeeW6',
        'active',
        0,
        NULL
    ),
    (
        '33333333-3333-3333-3333-333333333333',
        'locked_user',
        'locked@example.com',
        0,
        'Locked User',
        '$2a$10$v/ON07e5Z20EfAo5rtzVz.4joPtcrK/rkYlw6GC4DLWNAcaZbp8Gi',
        'locked',
        5,
        NULL
    );

-- OAuth clients
INSERT INTO
    oauth_clients (
        client_id,
        client_name,
        client_secret_hash,
        client_type,
        token_endpoint_auth_method,
        require_pkce,
        require_consent,
        access_token_ttl_seconds,
        refresh_token_ttl_seconds,
        id_token_ttl_seconds,
        status
    )
VALUES (
        'web-client',
        'Web Demo Client',
        '$2a$10$Sh4/YV14sDQcCE9v6JwMgeMMyPtiMi22Mvp5vzjUl2Kvo4f8GAHkW',
        'confidential',
        'client_secret_basic',
        1,
        1,
        3600,
        2592000,
        3600,
        'active'
    ),
    (
        'mobile-public-client',
        'Mobile Public Client',
        NULL,
        'public',
        'none',
        1,
        1,
        3600,
        2592000,
        3600,
        'active'
    ),
    (
        'service-client',
        'Backend Service Client',
        '$2a$10$Ta/cXlQfWf6x7E7iwPNI6OI1oJv1vsELVhxawptALNqlN0Pth3tRm',
        'confidential',
        'client_secret_basic',
        0,
        0,
        1800,
        0,
        0,
        'active'
    );

-- Redirect URIs
INSERT INTO
    oauth_client_redirect_uris (
        client_id,
        redirect_uri,
        redirect_uri_sha256
    )
SELECT id, 'http://localhost:3060/callback', SHA2(
        'http://localhost:3060/callback', 256
    )
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_redirect_uris (
        client_id,
        redirect_uri,
        redirect_uri_sha256
    )
SELECT id, 'http://localhost:8081/callback', SHA2(
        'http://localhost:8081/callback', 256
    )
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_redirect_uris (
        client_id,
        redirect_uri,
        redirect_uri_sha256
    )
SELECT id, 'http://127.0.0.1:3060/callback', SHA2(
        'http://127.0.0.1:3060/callback', 256
    )
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_redirect_uris (
        client_id,
        redirect_uri,
        redirect_uri_sha256
    )
SELECT id, 'myapp://callback', SHA2('myapp://callback', 256)
FROM oauth_clients
WHERE
    client_id = 'mobile-public-client';

-- Post logout redirect URIs
INSERT INTO
    oauth_client_post_logout_redirect_uris (
        client_id,
        redirect_uri,
        redirect_uri_sha256
    )
SELECT id, 'http://localhost:8081/', SHA2(
        'http://localhost:8081/', 256
    )
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_post_logout_redirect_uris (
        client_id,
        redirect_uri,
        redirect_uri_sha256
    )
SELECT id, 'http://127.0.0.1:8081/', SHA2(
        'http://127.0.0.1:8081/', 256
    )
FROM oauth_clients
WHERE
    client_id = 'web-client';

-- Grant types
INSERT INTO
    oauth_client_grant_types (client_id, grant_type)
SELECT id, 'authorization_code'
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_grant_types (client_id, grant_type)
SELECT id, 'refresh_token'
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_grant_types (client_id, grant_type)
SELECT id, 'authorization_code'
FROM oauth_clients
WHERE
    client_id = 'mobile-public-client';

INSERT INTO
    oauth_client_grant_types (client_id, grant_type)
SELECT id, 'refresh_token'
FROM oauth_clients
WHERE
    client_id = 'mobile-public-client';

INSERT INTO
    oauth_client_grant_types (client_id, grant_type)
SELECT id, 'client_credentials'
FROM oauth_clients
WHERE
    client_id = 'service-client';

-- Auth methods
INSERT INTO
    oauth_client_auth_methods (client_id, auth_method)
SELECT id, 'client_secret_basic'
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_auth_methods (client_id, auth_method)
SELECT id, 'none'
FROM oauth_clients
WHERE
    client_id = 'mobile-public-client';

INSERT INTO
    oauth_client_auth_methods (client_id, auth_method)
SELECT id, 'client_secret_basic'
FROM oauth_clients
WHERE
    client_id = 'service-client';

-- Scopes
INSERT INTO
    oauth_client_scopes (client_id, scope)
SELECT id, 'openid'
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_scopes (client_id, scope)
SELECT id, 'profile'
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_scopes (client_id, scope)
SELECT id, 'email'
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_scopes (client_id, scope)
SELECT id, 'offline_access'
FROM oauth_clients
WHERE
    client_id = 'web-client';

INSERT INTO
    oauth_client_scopes (client_id, scope)
SELECT id, 'openid'
FROM oauth_clients
WHERE
    client_id = 'mobile-public-client';

INSERT INTO
    oauth_client_scopes (client_id, scope)
SELECT id, 'profile'
FROM oauth_clients
WHERE
    client_id = 'mobile-public-client';

INSERT INTO
    oauth_client_scopes (client_id, scope)
SELECT id, 'offline_access'
FROM oauth_clients
WHERE
    client_id = 'mobile-public-client';

INSERT INTO
    oauth_client_scopes (client_id, scope)
SELECT id, 'internal.api.read'
FROM oauth_clients
WHERE
    client_id = 'service-client';

INSERT INTO
    oauth_client_scopes (client_id, scope)
SELECT id, 'internal.api.write'
FROM oauth_clients
WHERE
    client_id = 'service-client';

-- Sample consent
INSERT INTO
    oauth_consents (
        user_id,
        client_id,
        scopes_json,
        granted_at
    )
SELECT u.id, c.id, JSON_ARRAY('openid', 'profile', 'email'), NOW()
FROM users u
    JOIN oauth_clients c ON c.client_id = 'web-client'
WHERE
    u.username = 'alice';

-- Sample active JWK metadata
INSERT INTO
    jwk_keys (
        kid,
        kty,
        alg,
        use_type,
        public_jwk_json,
        private_key_ref,
        is_active,
        created_at,
        rotates_at,
        deactivated_at
    )
VALUES (
        'kid-2026-01-rs256',
        'RSA',
        'RS256',
        'sig',
        JSON_OBJECT(
            'kty',
            'RSA',
            'kid',
            'kid-2026-01-rs256',
            'use',
            'sig',
            'alg',
            'RS256',
            'n',
            'pFqjbNu3IvACehqIGssAnR4AtskQHJQqvwN1bhqco80wajHEZhz0fE4dPO4BfVhJvepvqrp8LIf3DTMzypGcKwBMpj6J5ds25-qkILk9gfKoBDas_onDbiqAJclishuT-GpEqx_igyd3Nj5fFXWcSxw5-nhFu_SZ1lKISEK_9QOe8MwWrjRaJcasDgWCIo6HTrT4PkWp48QvAMrFUFcXM2jw3GdeSlY5dDxWZsoGglJXAhCySAX4ZptIGsLwrWjXJDVmeqs849on1uI5N-PLEEu_ZWBUxKngTxVxWRquwAXT8n1wDU2woL6OPVjmB8K2pz7SRz9YFCXNzeUwkFFTTw',
            'e',
            'AQAB'
        ),
        'file://scripts/dev_keys/kid-2026-01-rs256.pem',
        1,
        NOW(),
        DATE_ADD(NOW(), INTERVAL 90 DAY),
        NULL
    );

-- Sample login session
INSERT INTO
    login_sessions (
        session_id,
        user_id,
        subject,
        acr,
        amr_json,
        ip_address,
        user_agent,
        authenticated_at,
        expires_at,
        logged_out_at
    )
SELECT 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', u.id, u.user_uuid, 'urn:idp:acr:pwd', JSON_ARRAY('pwd'), '127.0.0.1', 'seed-script', NOW(), DATE_ADD(NOW(), INTERVAL 8 HOUR), NULL
FROM users u
WHERE
    u.username = 'alice';

-- Sample authorization code
-- PKCE verifier fixture for sample_auth_code_abc123: verifier123
INSERT INTO
    oauth_authorization_codes (
        code,
        client_id,
        user_id,
        session_id,
        redirect_uri,
        scopes_json,
        state_value,
        nonce_value,
        code_challenge,
        code_challenge_method,
        expires_at,
        consumed_at
    )
SELECT 'sample_auth_code_abc123', c.id, u.id, s.id, 'http://localhost:3060/callback', JSON_ARRAY('openid', 'profile', 'email'), 'sample-state-001', 'sample-nonce-001', 'Z_P4EKbGwIkA01e3Y5fp4tMCvn_Ae5nUw7qY7XwkTrQ', 'S256', DATE_ADD(NOW(), INTERVAL 10 MINUTE), NULL
FROM
    oauth_clients c
    JOIN users u ON u.username = 'alice'
    JOIN login_sessions s ON s.session_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
WHERE
    c.client_id = 'web-client';

-- Sample access token
INSERT INTO
    oauth_access_tokens (
        token_value,
        token_sha256,
        client_id,
        user_id,
        subject,
        audience_json,
        scopes_json,
        token_type,
        token_format,
        issued_at,
        expires_at,
        revoked_at
    )
SELECT 'sample_access_token_value', SHA2(
        'sample_access_token_value', 256
    ), c.id, u.id, u.user_uuid, JSON_ARRAY('web-client'), JSON_ARRAY('openid', 'profile', 'email'), 'Bearer', 'jwt', NOW(), DATE_ADD(NOW(), INTERVAL 1 HOUR), NULL
FROM oauth_clients c
    JOIN users u ON u.username = 'alice'
WHERE
    c.client_id = 'web-client';

-- Sample refresh token
INSERT INTO
    oauth_refresh_tokens (
        token_value,
        token_sha256,
        client_id,
        user_id,
        subject,
        scopes_json,
        issued_at,
        expires_at,
        revoked_at,
        replaced_by_token_id
    )
SELECT 'sample_refresh_token_value', SHA2(
        'sample_refresh_token_value', 256
    ), c.id, u.id, u.user_uuid, JSON_ARRAY(
        'openid', 'profile', 'email', 'offline_access'
    ), NOW(), DATE_ADD(NOW(), INTERVAL 30 DAY), NULL, NULL
FROM oauth_clients c
    JOIN users u ON u.username = 'alice'
WHERE
    c.client_id = 'web-client';

-- Sample audit events
INSERT INTO
    audit_events (
        event_type,
        client_id,
        user_id,
        subject,
        session_id,
        ip_address,
        user_agent,
        metadata_json
    )
SELECT 'user.login.success', NULL, u.id, u.user_uuid, s.id, '127.0.0.1', 'seed-script', JSON_OBJECT('method', 'password')
FROM users u
    JOIN login_sessions s ON s.session_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
WHERE
    u.username = 'alice';

INSERT INTO
    audit_events (
        event_type,
        client_id,
        user_id,
        subject,
        session_id,
        ip_address,
        user_agent,
        metadata_json
    )
SELECT 'oauth.token.issued', c.id, u.id, u.user_uuid, s.id, '127.0.0.1', 'seed-script', JSON_OBJECT(
        'grant_type', 'authorization_code', 'scopes', JSON_ARRAY('openid', 'profile', 'email')
    )
FROM
    oauth_clients c
    JOIN users u ON u.username = 'alice'
    JOIN login_sessions s ON s.session_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
WHERE
    c.client_id = 'web-client';

-- =========================================================
-- Useful cleanup / maintenance examples
-- =========================================================
-- DELETE FROM oauth_authorization_codes WHERE expires_at < NOW() OR consumed_at IS NOT NULL;
-- DELETE FROM login_sessions WHERE expires_at < NOW() OR logged_out_at IS NOT NULL;
-- UPDATE oauth_access_tokens SET revoked_at = NOW() WHERE token_sha256 = SHA2(?, 256);
-- UPDATE oauth_refresh_tokens SET revoked_at = NOW() WHERE token_sha256 = SHA2(?, 256);

-- =========================================================
-- End
-- =========================================================
