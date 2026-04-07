SELECT
    id,
    session_id,
    user_id,
    subject,
    acr,
    amr_json,
    ip_address,
    user_agent,
    authenticated_at,
    expires_at,
    logged_out_at,
    created_at
FROM login_sessions
WHERE session_id = ?
LIMIT 1
