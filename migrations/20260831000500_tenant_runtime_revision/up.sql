ALTER TABLE tenant_runtime_bindings
    ADD COLUMN runtime_revision BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT ck_tenant_runtime_binding_revision CHECK (runtime_revision > 0);

