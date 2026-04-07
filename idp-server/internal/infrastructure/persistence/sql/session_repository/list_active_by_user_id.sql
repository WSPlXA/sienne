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
WHERE user_id = ?
  AND logged_out_at IS NULL
  AND expires_at > CURRENT_TIMESTAMP
ORDER BY authenticated_at DESC
