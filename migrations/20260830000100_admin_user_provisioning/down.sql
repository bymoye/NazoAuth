DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM admin_provision_receipts)
       OR EXISTS (
           SELECT 1
           FROM identity_security_events
           WHERE event_type = 'admin_user_created'
       ) THEN
        RAISE EXCEPTION
            'admin provisioning records exist; remove them explicitly before downgrading';
    END IF;
END
$$;

DROP INDEX uq_identity_security_event_admin_provision_request;
DROP TABLE admin_provision_receipts;

ALTER TABLE identity_security_events
    ALTER COLUMN request_id TYPE VARCHAR(64);

ALTER TABLE identity_security_events
    DROP CONSTRAINT ck_identity_security_event_type,
    DROP CONSTRAINT ck_identity_security_event_category_type,
    DROP CONSTRAINT ck_identity_security_event_semantics,
    DROP CONSTRAINT ck_identity_security_event_request_binding,
    ADD CONSTRAINT ck_identity_security_event_type
        CHECK (event_type IN (
            'mfa_totp_attempt', 'mfa_backup_code_attempt',
            'admin_user_update', 'initial_admin_bootstrap'
        )),
    ADD CONSTRAINT ck_identity_security_event_category_type CHECK (
        (category = 'mfa' AND event_type IN ('mfa_totp_attempt', 'mfa_backup_code_attempt'))
        OR (category = 'admin' AND event_type IN ('admin_user_update', 'initial_admin_bootstrap'))
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
        OR (event_type = 'initial_admin_bootstrap'
            AND outcome = 'success'
            AND reason_code = 'initial_admin_created')
    ),
    ADD CONSTRAINT ck_identity_security_event_bootstrap_binding CHECK (
        (event_type = 'initial_admin_bootstrap'
            AND request_id IS NOT NULL
            AND actor_id IS NULL
            AND target_user_id IS NOT NULL)
        OR (event_type <> 'initial_admin_bootstrap' AND request_id IS NULL)
    ),
    ADD CONSTRAINT ck_identity_security_event_request_id CHECK (
        request_id IS NULL OR request_id ~ '^bootstrap-admin-[0-9a-f]{32}$'
    );

CREATE TABLE initial_admin_bootstrap_receipts (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    token_hash VARCHAR(64) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    request_email_hash VARCHAR(64) NOT NULL,
    claimed_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_initial_admin_bootstrap_receipts_singleton CHECK (singleton),
    CONSTRAINT ck_initial_admin_bootstrap_receipts_token_hash_length
        CHECK (length(token_hash) = 64),
    CONSTRAINT ck_initial_admin_bootstrap_receipts_request_id
        CHECK (request_id ~ '^bootstrap-admin-[0-9a-f]{32}$'),
    CONSTRAINT ck_initial_admin_bootstrap_receipts_email_hash
        CHECK (request_email_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT uq_initial_admin_bootstrap_receipts_request_id UNIQUE (request_id),
    CONSTRAINT uq_initial_admin_bootstrap_receipts_claimed_user UNIQUE (claimed_user_id)
);

COMMENT ON TABLE initial_admin_bootstrap_receipts IS
    'Committed receipt for the single successful initial administrator claim; bootstrap authority remains in private runtime state.';
