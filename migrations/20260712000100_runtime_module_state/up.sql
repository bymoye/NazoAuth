CREATE TABLE runtime_module_desired_states (
    module_id VARCHAR(64) PRIMARY KEY,
    desired_mode VARCHAR(16) NOT NULL,
    revision BIGINT NOT NULL,
    actor_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    reason VARCHAR(500) NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_runtime_module_desired_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'native_sso', 'frontchannel_logout', 'session_management'
        )
    ),
    CONSTRAINT ck_runtime_module_desired_mode CHECK (
        desired_mode IN ('inherit', 'enabled', 'disabled')
    ),
    CONSTRAINT ck_runtime_module_desired_revision CHECK (revision > 0),
    CONSTRAINT ck_runtime_module_desired_reason CHECK (
        reason IS NULL OR char_length(btrim(reason)) BETWEEN 1 AND 500
    )
);

CREATE INDEX idx_runtime_module_desired_states_updated_at
    ON runtime_module_desired_states (updated_at DESC);

CREATE TABLE runtime_module_instance_states (
    instance_id VARCHAR(255) NOT NULL,
    module_id VARCHAR(64) NOT NULL,
    actual_state VARCHAR(16) NOT NULL,
    transition_revision BIGINT NOT NULL,
    applied_revision BIGINT NULL,
    drain_deadline TIMESTAMPTZ NULL,
    error_code VARCHAR(128) NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, module_id),
    CONSTRAINT ck_runtime_module_instance_id CHECK (
        char_length(btrim(instance_id)) BETWEEN 1 AND 255
    ),
    CONSTRAINT ck_runtime_module_instance_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'native_sso', 'frontchannel_logout', 'session_management'
        )
    ),
    CONSTRAINT ck_runtime_module_actual_state CHECK (
        actual_state IN ('disabled', 'starting', 'enabled', 'draining', 'failed')
    ),
    CONSTRAINT ck_runtime_module_transition_revision CHECK (transition_revision >= 0),
    CONSTRAINT ck_runtime_module_applied_revision CHECK (
        applied_revision IS NULL OR (
            applied_revision >= 0 AND applied_revision <= transition_revision
        )
    ),
    CONSTRAINT ck_runtime_module_instance_error_code CHECK (
        error_code IS NULL OR char_length(btrim(error_code)) BETWEEN 1 AND 128
    )
);

CREATE INDEX idx_runtime_module_instance_states_updated_at
    ON runtime_module_instance_states (updated_at DESC);
CREATE INDEX idx_runtime_module_instance_states_module_state
    ON runtime_module_instance_states (module_id, actual_state);

CREATE TABLE runtime_module_state_events (
    event_id UUID PRIMARY KEY,
    module_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    revision BIGINT NOT NULL,
    instance_id VARCHAR(255) NULL,
    actor_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    reason VARCHAR(500) NULL,
    before_state VARCHAR(16) NULL,
    after_state VARCHAR(16) NULL,
    outcome_code VARCHAR(128) NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_runtime_module_event_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'native_sso', 'frontchannel_logout', 'session_management'
        )
    ),
    CONSTRAINT ck_runtime_module_event_type CHECK (
        event_type IN (
            'desired_state_changed', 'transition_started', 'transition_completed',
            'transition_failed', 'drain_started', 'drain_completed',
            'stale_transition_discarded'
        )
    ),
    CONSTRAINT ck_runtime_module_event_revision CHECK (revision >= 0),
    CONSTRAINT ck_runtime_module_event_instance_id CHECK (
        instance_id IS NULL OR char_length(btrim(instance_id)) BETWEEN 1 AND 255
    ),
    CONSTRAINT ck_runtime_module_event_reason CHECK (
        reason IS NULL OR char_length(btrim(reason)) BETWEEN 1 AND 500
    ),
    CONSTRAINT ck_runtime_module_event_before_state CHECK (
        before_state IS NULL OR before_state IN (
            'inherit', 'disabled', 'starting', 'enabled', 'draining', 'failed'
        )
    ),
    CONSTRAINT ck_runtime_module_event_after_state CHECK (
        after_state IS NULL OR after_state IN (
            'inherit', 'disabled', 'starting', 'enabled', 'draining', 'failed'
        )
    ),
    CONSTRAINT ck_runtime_module_event_state_kind CHECK (
        (
            event_type = 'desired_state_changed'
            AND (before_state IS NULL OR before_state IN ('inherit', 'enabled', 'disabled'))
            AND (after_state IS NULL OR after_state IN ('inherit', 'enabled', 'disabled'))
        ) OR (
            event_type <> 'desired_state_changed'
            AND (before_state IS NULL OR before_state IN ('disabled', 'starting', 'enabled', 'draining', 'failed'))
            AND (after_state IS NULL OR after_state IN ('disabled', 'starting', 'enabled', 'draining', 'failed'))
        )
    ),
    CONSTRAINT ck_runtime_module_event_outcome_code CHECK (
        outcome_code IS NULL OR char_length(btrim(outcome_code)) BETWEEN 1 AND 128
    )
);

CREATE INDEX idx_runtime_module_state_events_occurred_at
    ON runtime_module_state_events (occurred_at DESC, event_id DESC);
CREATE INDEX idx_runtime_module_state_events_module_time
    ON runtime_module_state_events (module_id, occurred_at DESC, event_id DESC);
CREATE INDEX idx_runtime_module_state_events_actor_time
    ON runtime_module_state_events (actor_id, occurred_at DESC)
    WHERE actor_id IS NOT NULL;
