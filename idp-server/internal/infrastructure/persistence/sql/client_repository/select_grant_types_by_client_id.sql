SELECT grant_type
FROM oauth_client_grant_types
WHERE client_id = ?
ORDER BY id
