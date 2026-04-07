INSERT INTO operator_roles (
    role_code,
    display_name,
    description_text,
    privilege_mask,
    is_system
) VALUES (?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    display_name = VALUES(display_name),
    description_text = VALUES(description_text),
    privilege_mask = VALUES(privilege_mask),
    is_system = VALUES(is_system),
    updated_at = CURRENT_TIMESTAMP
