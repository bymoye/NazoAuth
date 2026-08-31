CREATE TABLE openid4vci_credential_datasets (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_id UUID NOT NULL,
    credential_configuration_id VARCHAR(255) NOT NULL,
    claims_ciphertext BYTEA NOT NULL,
    source VARCHAR(255) NOT NULL,
    valid_from TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vci_dataset_configuration_id
        CHECK (char_length(btrim(credential_configuration_id)) BETWEEN 1 AND 255),
    CONSTRAINT ck_openid4vci_dataset_ciphertext
        CHECK (octet_length(claims_ciphertext) BETWEEN 29 AND 1048576),
    CONSTRAINT ck_openid4vci_dataset_source
        CHECK (char_length(btrim(source)) BETWEEN 1 AND 255),
    CONSTRAINT ck_openid4vci_dataset_validity
        CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until > valid_from),
    CONSTRAINT fk_openid4vci_dataset_subject_tenant
        FOREIGN KEY (subject_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE CASCADE,
    PRIMARY KEY (tenant_id, subject_id, credential_configuration_id)
);

CREATE INDEX ix_openid4vci_credential_datasets_validity
    ON openid4vci_credential_datasets (tenant_id, subject_id, valid_until);

CREATE TABLE openid4vci_credential_dataset_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_id UUID NOT NULL,
    credential_configuration_id VARCHAR(255) NOT NULL,
    action SMALLINT NOT NULL,
    actor_user_id UUID NOT NULL,
    source VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vci_dataset_event_configuration_id
        CHECK (char_length(btrim(credential_configuration_id)) BETWEEN 1 AND 255),
    CONSTRAINT ck_openid4vci_dataset_event_action CHECK (action IN (1, 2)),
    CONSTRAINT ck_openid4vci_dataset_event_source
        CHECK (source = 'admin-session'),
    CONSTRAINT fk_openid4vci_dataset_event_subject_tenant
        FOREIGN KEY (subject_id, tenant_id) REFERENCES users(id, tenant_id) ON DELETE CASCADE,
    CONSTRAINT fk_openid4vci_dataset_event_actor_tenant
        FOREIGN KEY (actor_user_id, tenant_id) REFERENCES users(id, tenant_id)
);

CREATE INDEX ix_openid4vci_credential_dataset_events_subject
    ON openid4vci_credential_dataset_events
    (tenant_id, subject_id, credential_configuration_id, created_at DESC);
CREATE INDEX ix_openid4vci_credential_dataset_events_actor
    ON openid4vci_credential_dataset_events (tenant_id, actor_user_id, created_at DESC);

COMMENT ON TABLE openid4vci_credential_datasets IS
    'Application-encrypted issuer-authoritative credential claims. Protocol handlers never synthesize credential evidence from request inputs.';
COMMENT ON TABLE openid4vci_credential_dataset_events IS
    'Append-only administrative audit for credential dataset mutations; action 1=upsert, 2=delete.';
