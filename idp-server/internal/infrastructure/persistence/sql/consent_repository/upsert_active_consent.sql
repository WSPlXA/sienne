INSERT INTO oauth_consents (
    user_id,
    client_id,
    scopes_json,
    granted_at,
    revoked_at
) VALUES (?, ?, ?, ?, NULL)
ON DUPLICATE KEY UPDATE
    scopes_json = VALUES(scopes_json),
    granted_at = VALUES(granted_at),
    revoked_at = NULL
