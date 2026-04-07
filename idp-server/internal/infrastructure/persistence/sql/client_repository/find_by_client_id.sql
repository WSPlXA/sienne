SELECT
    id,
    client_id,
    client_name,
    client_secret_hash,
    client_type,
    token_endpoint_auth_method,
    require_pkce,
    require_consent,
    access_token_ttl_seconds,
    refresh_token_ttl_seconds,
    id_token_ttl_seconds,
    status,
    created_at,
    updated_at
FROM oauth_clients
WHERE client_id = ?
LIMIT 1
