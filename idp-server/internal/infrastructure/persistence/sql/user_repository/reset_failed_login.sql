UPDATE users
SET failed_login_count = 0,
    last_login_at = ?
WHERE id = ?
