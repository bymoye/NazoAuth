ALTER TABLE identity_security_events
    DROP CONSTRAINT IF EXISTS ck_identity_security_event_semantics;

ALTER TABLE identity_security_events
    ADD CONSTRAINT ck_identity_security_event_semantics CHECK (
        (event_type = 'mfa_totp_attempt' AND (
            (outcome = 'success' AND reason_code = 'totp_accepted')
            OR (outcome = 'invalid_credential' AND reason_code = 'totp_invalid')
            OR (outcome = 'replay' AND reason_code = 'totp_replay')
            OR (outcome = 'dependency_failure' AND reason_code = 'dependency_unavailable')
        ))
        OR (event_type = 'mfa_backup_code_attempt' AND (
            (outcome = 'success' AND reason_code = 'backup_code_accepted')
            OR (outcome = 'invalid_credential' AND reason_code = 'backup_code_invalid')
            OR (outcome = 'replay' AND reason_code = 'backup_code_replay')
            OR (outcome = 'dependency_failure' AND reason_code = 'dependency_unavailable')
        ))
        OR (event_type = 'admin_user_update' AND (
            (outcome = 'success' AND reason_code = 'admin_updated')
            OR (outcome = 'denied' AND reason_code IN (
                'target_not_found', 'actor_not_authorized', 'cross_tenant',
                'self_elevation', 'self_demotion_or_disable', 'target_at_or_above_actor',
                'grant_at_or_above_actor', 'invalid_role_level'
            ))
            OR (outcome = 'conflict' AND reason_code = 'dependency_unavailable')
            OR (outcome = 'dependency_failure' AND reason_code = 'dependency_unavailable')
        ))
    );
