SELECT
    id,
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
    revoked_at,
    created_at
FROM oauth_access_tokens
WHERE user_id = ?
  AND revoked_at IS NULL
  AND expires_at > CURRENT_TIMESTAMP
