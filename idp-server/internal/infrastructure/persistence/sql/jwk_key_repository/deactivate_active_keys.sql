UPDATE jwk_keys
SET is_active = 0,
    deactivated_at = CASE
        WHEN deactivated_at IS NULL OR deactivated_at > ? THEN ?
        ELSE deactivated_at
    END
WHERE is_active = 1
