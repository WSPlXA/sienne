UPDATE login_sessions
SET logged_out_at = ?
WHERE user_id = ?
  AND logged_out_at IS NULL
