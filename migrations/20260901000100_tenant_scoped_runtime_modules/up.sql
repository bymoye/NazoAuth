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

WITH modules(module_id, desired_mode) AS (
    VALUES
        ('device_authorization', 'enabled'), ('token_exchange', 'enabled'),
        ('jwt_bearer_grant', 'enabled'), ('ciba', 'enabled'),
        ('dynamic_client_registration', 'enabled'), ('request_objects', 'enabled'),
        ('jarm', 'enabled'), ('authorization_details', 'enabled'),
        ('http_message_signatures', 'disabled'), ('scim', 'enabled'),
        ('scim_security_events', 'enabled'), ('native_sso', 'enabled'),
        ('frontchannel_logout', 'enabled'), ('session_management', 'enabled'),
        ('openid4vci_issuer', 'enabled'), ('openid4vp_verifier', 'enabled')
), changed AS (
    INSERT INTO runtime_module_desired_states
        (tenant_id, module_id, desired_mode, revision, actor_id, reason, updated_at)
    SELECT tenant.id, modules.module_id, modules.desired_mode, 1, NULL,
           'tenant capability defaults', CURRENT_TIMESTAMP
    FROM tenants AS tenant
    CROSS JOIN modules
    ON CONFLICT (tenant_id, module_id) DO NOTHING
    RETURNING tenant_id, module_id, desired_mode, revision, actor_id, reason, updated_at
)
INSERT INTO runtime_module_state_events (
    event_id, tenant_id, module_id, event_type, revision, instance_id, actor_id,
    reason, before_state, after_state, outcome_code, occurred_at
)
SELECT uuidv7(), tenant_id, module_id, 'desired_state_changed', revision, NULL, actor_id,
       reason, NULL, desired_mode, NULL, updated_at
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
