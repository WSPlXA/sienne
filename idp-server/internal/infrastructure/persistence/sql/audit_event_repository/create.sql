INSERT INTO
    audit_events (
        event_type,
        client_id,
        user_id,
        subject,
        session_id,
        ip_address,
        user_agent,
        metadata_json
    )
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
