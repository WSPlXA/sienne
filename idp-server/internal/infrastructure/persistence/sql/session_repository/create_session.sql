INSERT INTO login_sessions (
    session_id,
    user_id,
    subject,
    acr,
    amr_json,
    ip_address,
    user_agent,
    authenticated_at,
    expires_at,
    logged_out_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
