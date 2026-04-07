SELECT id, user_id, secret, enabled_at, created_at, updated_at
FROM user_totp_credentials
WHERE user_id = ?
LIMIT 1
