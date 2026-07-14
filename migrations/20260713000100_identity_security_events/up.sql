CREATE TABLE identity_security_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    category VARCHAR(16) NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    outcome VARCHAR(32) NOT NULL,
    actor_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    target_user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    reason_code VARCHAR(64) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_identity_security_event_category CHECK (category IN ('mfa', 'admin')),
    CONSTRAINT ck_identity_security_event_type CHECK (
        event_type IN ('mfa_totp_attempt', 'mfa_backup_code_attempt', 'admin_user_update')
    ),
    CONSTRAINT ck_identity_security_event_category_type CHECK (
        (category = 'mfa' AND event_type IN ('mfa_totp_attempt', 'mfa_backup_code_attempt'))
        OR (category = 'admin' AND event_type = 'admin_user_update')
    ),
    CONSTRAINT ck_identity_security_event_outcome CHECK (
        outcome IN ('success', 'denied', 'invalid_credential', 'replay', 'conflict', 'dependency_failure')
    ),
    CONSTRAINT ck_identity_security_event_reason_code CHECK (
        char_length(reason_code) BETWEEN 1 AND 64
        AND reason_code ~ '^[a-z0-9_]+$'
    ),
    CONSTRAINT ck_identity_security_event_semantics CHECK (
        (event_type = 'mfa_totp_attempt' AND (
            (outcome = 'success' AND reason_code = 'totp_accepted')
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
    )
);

CREATE INDEX idx_identity_security_events_tenant_time
    ON identity_security_events (tenant_id, occurred_at DESC);
CREATE INDEX idx_identity_security_events_actor_time
    ON identity_security_events (actor_id, occurred_at DESC)
    WHERE actor_id IS NOT NULL;
CREATE INDEX idx_identity_security_events_target_time
    ON identity_security_events (target_user_id, occurred_at DESC)
    WHERE target_user_id IS NOT NULL;
