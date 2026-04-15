SELECT
    id,
    event_id,
    event_type,
    client_id,
    user_id,
    subject,
    session_id,
    ip_address,
    user_agent,
    CAST(metadata_json AS CHAR) AS metadata_json_text,
    created_at
FROM audit_events
