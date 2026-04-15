INSERT INTO
    audit_events (
        event_id,
        event_type,
        client_id,
        user_id,
        subject,
        session_id,
        ip_address,
        user_agent,
        metadata_json
    )
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    event_type = VALUES(event_type),
    client_id = VALUES(client_id),
    user_id = VALUES(user_id),
    subject = VALUES(subject),
    session_id = VALUES(session_id),
    ip_address = VALUES(ip_address),
    user_agent = VALUES(user_agent),
    metadata_json = VALUES(metadata_json);
