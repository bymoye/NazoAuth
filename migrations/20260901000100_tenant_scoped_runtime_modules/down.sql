DROP INDEX idx_runtime_module_state_events_actor_time;
DROP INDEX idx_runtime_module_state_events_module_time;
DROP INDEX idx_runtime_module_state_events_occurred_at;
CREATE INDEX idx_runtime_module_state_events_occurred_at
    ON runtime_module_state_events (occurred_at DESC, event_id DESC);
CREATE INDEX idx_runtime_module_state_events_module_time
    ON runtime_module_state_events (module_id, occurred_at DESC, event_id DESC);
CREATE INDEX idx_runtime_module_state_events_actor_time
    ON runtime_module_state_events (actor_id, occurred_at DESC)
    WHERE actor_id IS NOT NULL;

DROP INDEX idx_runtime_module_instance_states_module_state;
CREATE INDEX idx_runtime_module_instance_states_module_state
    ON runtime_module_instance_states (module_id, actual_state);

DELETE FROM runtime_module_state_events
WHERE tenant_id <> '00000000-0000-0000-0000-000000000001'::uuid;
DELETE FROM runtime_module_instance_states
WHERE tenant_id <> '00000000-0000-0000-0000-000000000001'::uuid;
DELETE FROM runtime_module_desired_states
WHERE tenant_id <> '00000000-0000-0000-0000-000000000001'::uuid;

ALTER TABLE runtime_module_state_events
    DROP CONSTRAINT fk_runtime_module_event_tenant,
    DROP COLUMN tenant_id;

ALTER TABLE runtime_module_instance_states
    DROP CONSTRAINT fk_runtime_module_instance_tenant,
    DROP CONSTRAINT runtime_module_instance_states_pkey,
    DROP COLUMN tenant_id,
    ADD CONSTRAINT runtime_module_instance_states_pkey PRIMARY KEY (instance_id, module_id);

ALTER TABLE runtime_module_desired_states
    DROP CONSTRAINT fk_runtime_module_desired_tenant,
    DROP CONSTRAINT runtime_module_desired_states_pkey,
    DROP COLUMN tenant_id,
    ADD CONSTRAINT runtime_module_desired_states_pkey PRIMARY KEY (module_id);
