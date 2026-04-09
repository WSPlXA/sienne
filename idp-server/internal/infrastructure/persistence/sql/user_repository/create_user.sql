INSERT INTO users (
    user_uuid,
    username,
    email,
    email_verified,
    display_name,
    password_hash,
    role_code,
    privilege_mask,
    tenant_scope,
    status,
    failed_login_count,
    last_login_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
