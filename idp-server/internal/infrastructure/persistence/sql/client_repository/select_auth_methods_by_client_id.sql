SELECT auth_method
FROM oauth_client_auth_methods
WHERE client_id = ?
ORDER BY id
