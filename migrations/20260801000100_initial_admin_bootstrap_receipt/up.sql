ALTER TABLE initial_admin_bootstrap
    ADD COLUMN request_id VARCHAR(64),
    ADD COLUMN request_email_hash VARCHAR(64),
    ADD COLUMN claimed_user_id UUID REFERENCES users(id) ON DELETE RESTRICT,
    ADD COLUMN claim_result VARCHAR(16),
    ADD COLUMN receipt_version SMALLINT,
    ADD COLUMN claimed_at TIMESTAMPTZ;

ALTER TABLE initial_admin_bootstrap
    ADD CONSTRAINT ck_initial_admin_bootstrap_request_id
        CHECK (
            request_id IS NULL
            OR request_id ~ '^bootstrap-admin-[0-9a-f]{32}$'
        ),
    ADD CONSTRAINT ck_initial_admin_bootstrap_email_hash
        CHECK (
            request_email_hash IS NULL
            OR request_email_hash ~ '^[0-9a-f]{64}$'
        ),
    ADD CONSTRAINT ck_initial_admin_bootstrap_claim_result
        CHECK (claim_result IS NULL OR claim_result = 'created'),
    ADD CONSTRAINT ck_initial_admin_bootstrap_receipt_version
        CHECK (receipt_version IS NULL OR receipt_version = 1),
    ADD CONSTRAINT ck_initial_admin_bootstrap_closed_receipt
        CHECK (
            (
                consumed_at IS NULL
                AND request_id IS NULL
                AND request_email_hash IS NULL
                AND claimed_user_id IS NULL
                AND claim_result IS NULL
                AND receipt_version IS NULL
                AND claimed_at IS NULL
            )
            OR
            (
                consumed_at IS NOT NULL
                AND (
                    (
                        request_id IS NULL
                        AND request_email_hash IS NULL
                        AND claimed_user_id IS NULL
                        AND claim_result IS NULL
                        AND receipt_version IS NULL
                        AND claimed_at IS NULL
                    )
                    OR
                    (
                        request_id IS NOT NULL
                        AND request_email_hash IS NOT NULL
                        AND claimed_user_id IS NOT NULL
                        AND claim_result = 'created'
                        AND receipt_version = 1
                        AND claimed_at IS NOT NULL
                    )
                )
            )
        ),
    ADD CONSTRAINT uq_initial_admin_bootstrap_request_id UNIQUE (request_id),
    ADD CONSTRAINT uq_initial_admin_bootstrap_claimed_user UNIQUE (claimed_user_id);

COMMENT ON COLUMN initial_admin_bootstrap.request_id IS
    'Non-secret controller request identity for idempotent receipt replay.';
COMMENT ON COLUMN initial_admin_bootstrap.request_email_hash IS
    'SHA-256 binding of the normalized claimed email; no password or plaintext token is stored.';
COMMENT ON COLUMN initial_admin_bootstrap.claimed_user_id IS
    'Administrator created by the atomic claim transaction.';
COMMENT ON COLUMN initial_admin_bootstrap.claim_result IS
    'Closed application receipt outcome; currently only created.';
COMMENT ON COLUMN initial_admin_bootstrap.receipt_version IS
    'Version of the stable application receipt contract.';

ALTER TABLE identity_security_events
    ADD COLUMN request_id VARCHAR(64),
    DROP CONSTRAINT ck_identity_security_event_category,
    DROP CONSTRAINT ck_identity_security_event_type,
    DROP CONSTRAINT ck_identity_security_event_category_type,
    DROP CONSTRAINT ck_identity_security_event_semantics,
    ADD CONSTRAINT ck_identity_security_event_category
        CHECK (category IN ('mfa', 'admin')),
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

CREATE UNIQUE INDEX uq_identity_security_event_bootstrap_request
    ON identity_security_events (request_id)
    WHERE event_type = 'initial_admin_bootstrap';
