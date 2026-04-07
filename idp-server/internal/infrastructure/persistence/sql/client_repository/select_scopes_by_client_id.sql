SELECT scope
FROM oauth_client_scopes
WHERE client_id = ?
ORDER BY id
