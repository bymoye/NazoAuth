CREATE TABLE runtime_module_default_policy (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    version INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_runtime_module_default_policy_singleton CHECK (singleton),
    CONSTRAINT ck_runtime_module_default_policy_version CHECK (version >= 1)
);

INSERT INTO runtime_module_default_policy (singleton, version)
VALUES (TRUE, 1);

ALTER TABLE oauth_clients
    ADD COLUMN security_policy JSONB;

ALTER TABLE oauth_clients
    ADD CONSTRAINT ck_oauth_clients_security_policy_object
    CHECK (
        security_policy IS NULL
        OR jsonb_typeof(security_policy) = 'object'
    );
