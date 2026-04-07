INSERT INTO oauth_authorization_codes (
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
    consumed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
