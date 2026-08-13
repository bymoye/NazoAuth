DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM initial_admin_bootstrap WHERE request_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM identity_security_events
        WHERE event_type = 'initial_admin_bootstrap'
    ) THEN
        RAISE EXCEPTION 'cannot remove initial administrator receipts or audit evidence';
    END IF;
END
$$;

DROP INDEX IF EXISTS uq_identity_security_event_bootstrap_request;

ALTER TABLE identity_security_events
    DROP CONSTRAINT ck_identity_security_event_request_id,
    DROP CONSTRAINT ck_identity_security_event_bootstrap_binding,
    DROP CONSTRAINT ck_identity_security_event_semantics,
    DROP CONSTRAINT ck_identity_security_event_category_type,
    DROP CONSTRAINT ck_identity_security_event_type,
    DROP CONSTRAINT ck_identity_security_event_category,
    DROP COLUMN request_id,
    ADD CONSTRAINT ck_identity_security_event_category CHECK (category IN ('mfa', 'admin')),
    ADD CONSTRAINT ck_identity_security_event_type CHECK (
        event_type IN ('mfa_totp_attempt', 'mfa_backup_code_attempt', 'admin_user_update')
    ),
    ADD CONSTRAINT ck_identity_security_event_category_type CHECK (
        (category = 'mfa' AND event_type IN ('mfa_totp_attempt', 'mfa_backup_code_attempt'))
        OR (category = 'admin' AND event_type = 'admin_user_update')
    ),
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

ALTER TABLE initial_admin_bootstrap
    DROP CONSTRAINT IF EXISTS uq_initial_admin_bootstrap_claimed_user,
    DROP CONSTRAINT IF EXISTS uq_initial_admin_bootstrap_request_id,
    DROP CONSTRAINT IF EXISTS ck_initial_admin_bootstrap_closed_receipt,
    DROP CONSTRAINT IF EXISTS ck_initial_admin_bootstrap_claim_result,
    DROP CONSTRAINT IF EXISTS ck_initial_admin_bootstrap_receipt_version,
    DROP CONSTRAINT IF EXISTS ck_initial_admin_bootstrap_email_hash,
    DROP CONSTRAINT IF EXISTS ck_initial_admin_bootstrap_request_id,
    DROP COLUMN IF EXISTS claimed_at,
    DROP COLUMN IF EXISTS claim_result,
    DROP COLUMN IF EXISTS receipt_version,
    DROP COLUMN IF EXISTS claimed_user_id,
    DROP COLUMN IF EXISTS request_email_hash,
    DROP COLUMN IF EXISTS request_id;
