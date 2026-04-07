SELECT redirect_uri
FROM oauth_client_redirect_uris
WHERE client_id = ?
ORDER BY id
