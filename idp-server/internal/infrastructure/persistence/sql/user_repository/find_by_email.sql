SELECT
    id,
    user_uuid,
    username,
    email,
    email_verified,
    display_name,
    password_hash,
    status,
    failed_login_count,
    last_login_at,
    created_at,
    updated_at
FROM users
WHERE email = ?
LIMIT 1
