UPDATE oauth_access_tokens
SET revoked_at = ?
WHERE user_id = ?
  AND revoked_at IS NULL
  AND expires_at > CURRENT_TIMESTAMP
