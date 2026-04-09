INSERT INTO user_webauthn_credentials (
    user_id,
    credential_id,
    credential_json,
    last_used_at,
    created_at,
    updated_at
) VALUES (?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    user_id = VALUES(user_id),
    credential_json = VALUES(credential_json),
    last_used_at = VALUES(last_used_at),
    updated_at = VALUES(updated_at)

