INSERT INTO oauth_access_tokens (
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
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
