SELECT
    id,
    role_code,
    display_name,
    description_text,
    privilege_mask,
    is_system,
    created_at,
    updated_at
FROM operator_roles
ORDER BY role_code ASC
