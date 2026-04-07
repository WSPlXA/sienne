SELECT
    id,
    code,
    client_id,
    user_id,
    session_id,
    redirect_uri,
    scopes_json,
    state_value,
    nonce_value,
    code_challenge,
    code_challenge_method,
    expires_at,
    consumed_at,
    created_at
FROM oauth_authorization_codes
WHERE code = ?
FOR UPDATE
