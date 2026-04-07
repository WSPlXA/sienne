INSERT INTO user_totp_credentials (user_id, secret, enabled_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    secret = VALUES(secret),
    enabled_at = VALUES(enabled_at),
    updated_at = VALUES(updated_at)
