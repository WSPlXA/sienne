SELECT scopes_json
FROM oauth_consents
WHERE user_id = ?
  AND client_id = ?
  AND revoked_at IS NULL
LIMIT 1
