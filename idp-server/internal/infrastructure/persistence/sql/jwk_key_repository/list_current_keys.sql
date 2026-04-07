SELECT
    id,
    kid,
    kty,
    alg,
    use_type,
    public_jwk_json,
    private_key_ref,
    is_active,
    created_at,
    rotates_at,
    deactivated_at
FROM jwk_keys
WHERE deactivated_at IS NULL OR deactivated_at > UTC_TIMESTAMP()
ORDER BY is_active DESC, created_at DESC, id DESC
