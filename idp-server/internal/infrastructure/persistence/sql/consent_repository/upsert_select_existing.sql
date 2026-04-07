SELECT scopes_json
FROM oauth_consents
WHERE user_id = ?
  AND client_id = ?
LIMIT 1
