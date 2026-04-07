INSERT INTO jwk_keys (
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
) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, NULL)
