UPDATE users
SET role_code = ?,
    privilege_mask = ?,
    tenant_scope = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE id = ?
