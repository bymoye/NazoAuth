DROP TABLE IF EXISTS initial_admin_bootstrap_receipts;

CREATE TABLE admin_provision_receipts (
    operation_id VARCHAR(128) PRIMARY KEY,
    deployment_id VARCHAR(128) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_admin_provision_receipts_operation_id
        CHECK (operation_id ~ '^[-A-Za-z0-9._:+]{1,128}$'),
    CONSTRAINT ck_admin_provision_receipts_deployment_id
        CHECK (deployment_id ~ '^[-A-Za-z0-9._:+]{1,128}$')
);

CREATE UNIQUE INDEX uq_admin_provision_receipts_user
    ON admin_provision_receipts (user_id);

ALTER TABLE identity_security_events
    ALTER COLUMN request_id TYPE VARCHAR(128);

ALTER TABLE identity_security_events
    DROP CONSTRAINT ck_identity_security_event_type,
    DROP CONSTRAINT ck_identity_security_event_category_type,
    DROP CONSTRAINT ck_identity_security_event_semantics,
    DROP CONSTRAINT ck_identity_security_event_bootstrap_binding,
    DROP CONSTRAINT ck_identity_security_event_request_id,
    ADD CONSTRAINT ck_identity_security_event_type
        CHECK (event_type IN (
            'mfa_totp_attempt', 'mfa_backup_code_attempt',
            'admin_user_update', 'initial_admin_bootstrap', 'admin_user_created'
        )),
    ADD CONSTRAINT ck_identity_security_event_category_type CHECK (
        (category = 'mfa' AND event_type IN ('mfa_totp_attempt', 'mfa_backup_code_attempt'))
        OR (category = 'admin' AND event_type IN (
            'admin_user_update', 'initial_admin_bootstrap', 'admin_user_created'
        ))
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
        OR (event_type = 'admin_user_created'
            AND outcome = 'success'
            AND reason_code = 'admin_created')
    ),
    ADD CONSTRAINT ck_identity_security_event_request_binding CHECK (
        (event_type = 'initial_admin_bootstrap'
            AND request_id IS NOT NULL
            AND request_id ~ '^bootstrap-admin-[0-9a-f]{32}$'
            AND actor_id IS NULL
            AND target_user_id IS NOT NULL)
        OR (event_type = 'admin_user_created'
            AND request_id IS NOT NULL
            AND request_id ~ '^[-A-Za-z0-9._:+]{1,128}$'
            AND actor_id IS NULL
            AND target_user_id IS NOT NULL)
        OR (event_type NOT IN ('initial_admin_bootstrap', 'admin_user_created')
            AND request_id IS NULL)
    );

CREATE UNIQUE INDEX uq_identity_security_event_admin_provision_request
    ON identity_security_events (request_id)
    WHERE event_type = 'admin_user_created';

COMMENT ON TABLE admin_provision_receipts IS
    'Durable idempotency receipt for local controller administrator provisioning.';
COMMENT ON COLUMN admin_provision_receipts.operation_id IS
    'Controller operation identity; retries of the same delivered operation return this receipt.';
