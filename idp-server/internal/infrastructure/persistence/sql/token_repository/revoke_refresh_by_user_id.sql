UPDATE oauth_refresh_tokens
SET revoked_at = ?
WHERE user_id = ?
  AND revoked_at IS NULL
  AND replaced_by_token_id IS NULL
  AND expires_at > CURRENT_TIMESTAMP
