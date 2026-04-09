UPDATE user_webauthn_credentials
SET
    last_used_at = ?,
    updated_at = UTC_TIMESTAMP()
WHERE credential_id = ?

