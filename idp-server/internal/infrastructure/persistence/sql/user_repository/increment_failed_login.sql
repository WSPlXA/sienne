UPDATE users
SET failed_login_count = failed_login_count + 1
WHERE id = ?
