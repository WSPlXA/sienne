SELECT
    id,
    user_id,
    credential_id,
    credential_json,
    last_used_at,
    created_at,
    updated_at
FROM user_webauthn_credentials
WHERE user_id = ?
ORDER BY id ASC

