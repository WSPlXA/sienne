UPDATE operator_roles
SET display_name = ?,
    description_text = ?,
    privilege_mask = ?,
    updated_at = CURRENT_TIMESTAMP
WHERE role_code = ?
