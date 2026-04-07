SELECT 1
FROM oauth_client_post_logout_redirect_uris
WHERE client_id = ? AND redirect_uri_sha256 = ?
LIMIT 1
