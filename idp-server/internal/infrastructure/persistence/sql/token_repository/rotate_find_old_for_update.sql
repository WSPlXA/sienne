SELECT
    id,
    token_value,
    token_sha256,
    client_id,
    user_id,
    subject,
    scopes_json,
    issued_at,
    expires_at,
    revoked_at,
    replaced_by_token_id,
    created_at
FROM oauth_refresh_tokens
WHERE token_sha256 = ?
FOR UPDATE
