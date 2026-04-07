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
WHERE user_id = ?
  AND revoked_at IS NULL
  AND replaced_by_token_id IS NULL
  AND expires_at > CURRENT_TIMESTAMP
