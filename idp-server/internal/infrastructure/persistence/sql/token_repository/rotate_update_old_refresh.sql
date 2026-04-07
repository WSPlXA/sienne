UPDATE oauth_refresh_tokens
SET revoked_at = ?, replaced_by_token_id = ?
WHERE id = ?
