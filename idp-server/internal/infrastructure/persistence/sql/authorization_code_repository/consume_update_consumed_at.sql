UPDATE oauth_authorization_codes
SET consumed_at = ?
WHERE id = ?
  AND consumed_at IS NULL
