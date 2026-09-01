ALTER TABLE runtime_module_desired_states
    ADD COLUMN tenant_id UUID;

UPDATE runtime_module_desired_states
SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid;

ALTER TABLE runtime_module_desired_states
    ALTER COLUMN tenant_id SET NOT NULL,
    DROP CONSTRAINT runtime_module_desired_states_pkey,
    ADD CONSTRAINT runtime_module_desired_states_pkey PRIMARY KEY (tenant_id, module_id),
    ADD CONSTRAINT fk_runtime_module_desired_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE runtime_module_instance_states
    ADD COLUMN tenant_id UUID;

UPDATE runtime_module_instance_states
SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid;

ALTER TABLE runtime_module_instance_states
    ALTER COLUMN tenant_id SET NOT NULL,
    DROP CONSTRAINT runtime_module_instance_states_pkey,
    ADD CONSTRAINT runtime_module_instance_states_pkey
        PRIMARY KEY (tenant_id, instance_id, module_id),
    ADD CONSTRAINT fk_runtime_module_instance_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

ALTER TABLE runtime_module_state_events
    ADD COLUMN tenant_id UUID;

UPDATE runtime_module_state_events
SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid;

ALTER TABLE runtime_module_state_events
    ALTER COLUMN tenant_id SET NOT NULL,
    ADD CONSTRAINT fk_runtime_module_event_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

WITH modules(module_id) AS (
    VALUES
        ('device_authorization'), ('token_exchange'), ('jwt_bearer_grant'), ('ciba'),
        ('dynamic_client_registration'), ('request_objects'), ('jarm'),
        ('authorization_details'), ('http_message_signatures'), ('scim'),
        ('scim_security_events'), ('native_sso'), ('frontchannel_logout'),
        ('session_management'), ('openid4vci_issuer'), ('openid4vp_verifier')
), changed AS (
    INSERT INTO runtime_module_desired_states
        (tenant_id, module_id, desired_mode, revision, actor_id, reason, updated_at)
    SELECT tenant.id, modules.module_id, 'enabled', 1, NULL,
           'tenant full capability baseline', CURRENT_TIMESTAMP
    FROM tenants AS tenant
    CROSS JOIN modules
    ON CONFLICT (tenant_id, module_id) DO UPDATE
    SET desired_mode = 'enabled',
        revision = runtime_module_desired_states.revision + 1,
        actor_id = NULL,
        reason = 'tenant full capability baseline',
        updated_at = CURRENT_TIMESTAMP
    WHERE runtime_module_desired_states.desired_mode <> 'enabled'
    RETURNING tenant_id, module_id, revision, actor_id, reason, updated_at
)
INSERT INTO runtime_module_state_events (
    event_id, tenant_id, module_id, event_type, revision, instance_id, actor_id,
    reason, before_state, after_state, outcome_code, occurred_at
)
SELECT uuidv7(), tenant_id, module_id, 'desired_state_changed', revision, NULL, actor_id,
       reason, NULL, 'enabled', NULL, updated_at
FROM changed;

DROP INDEX idx_runtime_module_instance_states_module_state;
CREATE INDEX idx_runtime_module_instance_states_module_state
    ON runtime_module_instance_states (tenant_id, module_id, actual_state);

DROP INDEX idx_runtime_module_state_events_occurred_at;
DROP INDEX idx_runtime_module_state_events_module_time;
DROP INDEX idx_runtime_module_state_events_actor_time;
CREATE INDEX idx_runtime_module_state_events_occurred_at
    ON runtime_module_state_events (tenant_id, occurred_at DESC, event_id DESC);
CREATE INDEX idx_runtime_module_state_events_module_time
    ON runtime_module_state_events (tenant_id, module_id, occurred_at DESC, event_id DESC);
CREATE INDEX idx_runtime_module_state_events_actor_time
    ON runtime_module_state_events (tenant_id, actor_id, occurred_at DESC)
    WHERE actor_id IS NOT NULL;
