ALTER TABLE runtime_module_desired_states
    DROP CONSTRAINT ck_runtime_module_desired_module_id,
    ADD CONSTRAINT ck_runtime_module_desired_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'scim_security_events', 'native_sso', 'frontchannel_logout',
            'session_management', 'openid4vci_issuer', 'openid4vp_verifier'
        )
    );

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS ck_oauth_clients_token_endpoint_auth_method_value,
    ADD CONSTRAINT ck_oauth_clients_token_endpoint_auth_method_value CHECK (
        token_endpoint_auth_method IN (
            'none', 'client_secret_basic', 'client_secret_post', 'private_key_jwt',
            'tls_client_auth', 'self_signed_tls_client_auth', 'attest_jwt_client_auth'
        )
    );

ALTER TABLE runtime_module_instance_states
    DROP CONSTRAINT ck_runtime_module_instance_module_id,
    ADD CONSTRAINT ck_runtime_module_instance_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'scim_security_events', 'native_sso', 'frontchannel_logout',
            'session_management', 'openid4vci_issuer', 'openid4vp_verifier'
        )
    );

ALTER TABLE runtime_module_state_events
    DROP CONSTRAINT ck_runtime_module_event_module_id,
    ADD CONSTRAINT ck_runtime_module_event_module_id CHECK (
        module_id IN (
            'device_authorization', 'token_exchange', 'jwt_bearer_grant', 'ciba',
            'dynamic_client_registration', 'request_objects', 'jarm',
            'authorization_details', 'http_message_signatures', 'scim',
            'scim_security_events', 'native_sso', 'frontchannel_logout',
            'session_management', 'openid4vci_issuer', 'openid4vp_verifier'
        )
    );

CREATE TABLE openid4vci_credential_configurations (
    id VARCHAR(255) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    configuration JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vci_configuration_id
        CHECK (char_length(btrim(id)) BETWEEN 1 AND 255),
    CONSTRAINT ck_openid4vci_configuration_object
        CHECK (jsonb_typeof(configuration) = 'object' AND configuration <> '{}'::jsonb),
    PRIMARY KEY (tenant_id, id)
);

CREATE TABLE openid4vci_offers (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_id UUID REFERENCES users(id) ON DELETE CASCADE,
    credential_configuration_ids JSONB NOT NULL,
    grants_ciphertext BYTEA NOT NULL,
    issuer_state_hash VARCHAR(64),
    pre_authorized_code_hash VARCHAR(64),
    tx_code_hash VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vci_offer_configuration_ids
        CHECK (jsonb_typeof(credential_configuration_ids) = 'array'
            AND jsonb_array_length(credential_configuration_ids) > 0),
    CONSTRAINT ck_openid4vci_offer_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_openid4vci_offer_consumed CHECK (
        consumed_at IS NULL OR consumed_at >= created_at
    )
);

CREATE UNIQUE INDEX ux_openid4vci_offer_issuer_state_hash
    ON openid4vci_offers (issuer_state_hash) WHERE issuer_state_hash IS NOT NULL;
CREATE UNIQUE INDEX ux_openid4vci_offer_pre_authorized_code_hash
    ON openid4vci_offers (pre_authorized_code_hash)
    WHERE pre_authorized_code_hash IS NOT NULL;
CREATE INDEX ix_openid4vci_offer_expiry ON openid4vci_offers (expires_at);

CREATE TABLE openid4vci_access_grants (
    token_id UUID PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    credential_configuration_ids JSONB NOT NULL,
    credential_identifiers JSONB NOT NULL,
    dpop_jkt VARCHAR(128),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vci_access_configuration_ids
        CHECK (jsonb_typeof(credential_configuration_ids) = 'array'
            AND jsonb_array_length(credential_configuration_ids) > 0),
    CONSTRAINT ck_openid4vci_access_identifiers
        CHECK (jsonb_typeof(credential_identifiers) = 'array'),
    CONSTRAINT ck_openid4vci_access_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_openid4vci_access_dpop CHECK (
        dpop_jkt IS NULL OR char_length(btrim(dpop_jkt)) BETWEEN 20 AND 128
    )
);

CREATE INDEX ix_openid4vci_access_expiry ON openid4vci_access_grants (expires_at);

CREATE TABLE openid4vci_nonces (
    nonce_hash VARCHAR(64) PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vci_nonce_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_openid4vci_nonce_consumed CHECK (
        consumed_at IS NULL OR consumed_at >= created_at
    )
);

CREATE INDEX ix_openid4vci_nonce_expiry ON openid4vci_nonces (expires_at);

CREATE TABLE openid4vci_deferred_transactions (
    id UUID PRIMARY KEY,
    transaction_hash VARCHAR(64) NOT NULL UNIQUE,
    token_id UUID NOT NULL REFERENCES openid4vci_access_grants(token_id) ON DELETE CASCADE,
    credential_configuration_id VARCHAR(255) NOT NULL,
    credential_format VARCHAR(32) NOT NULL,
    holder_bindings JSONB NOT NULL,
    payload_ciphertext BYTEA NOT NULL,
    ready_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vci_deferred_format
        CHECK (credential_format IN ('dc+sd-jwt', 'mso_mdoc')),
    CONSTRAINT ck_openid4vci_deferred_holder_bindings
        CHECK (jsonb_typeof(holder_bindings) = 'array'
            AND jsonb_array_length(holder_bindings) > 0),
    CONSTRAINT ck_openid4vci_deferred_times
        CHECK (ready_at >= created_at AND expires_at > ready_at),
    CONSTRAINT ck_openid4vci_deferred_consumed CHECK (
        consumed_at IS NULL OR consumed_at >= ready_at
    )
);

CREATE INDEX ix_openid4vci_deferred_expiry
    ON openid4vci_deferred_transactions (expires_at);

CREATE TABLE openid4vci_notifications (
    notification_id VARCHAR(128) PRIMARY KEY,
    token_id UUID NOT NULL REFERENCES openid4vci_access_grants(token_id) ON DELETE CASCADE,
    event VARCHAR(32),
    description VARCHAR(1024),
    expires_at TIMESTAMPTZ NOT NULL,
    occurred_at TIMESTAMPTZ,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vci_notification_event CHECK (
        event IS NULL OR event IN ('credential_accepted', 'credential_failure', 'credential_deleted')
    ),
    CONSTRAINT ck_openid4vci_notification_description CHECK (
        description IS NULL OR char_length(btrim(description)) BETWEEN 1 AND 1024
    ),
    CONSTRAINT ck_openid4vci_notification_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_openid4vci_notification_terminal CHECK (
        (event IS NULL AND occurred_at IS NULL)
        OR (event IS NOT NULL AND occurred_at IS NOT NULL)
    )
);

CREATE TABLE openid4vp_transactions (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id_prefix VARCHAR(32) NOT NULL,
    request_method VARCHAR(32) NOT NULL,
    response_mode VARCHAR(32) NOT NULL,
    wallet_authorization_endpoint TEXT NOT NULL,
    state_hash VARCHAR(64) NOT NULL UNIQUE,
    request JSONB NOT NULL,
    request_object TEXT,
    request_uri TEXT,
    ephemeral_private_key_ciphertext BYTEA,
    result_ciphertext BYTEA,
    completed_at TIMESTAMPTZ,
    create_request_jti VARCHAR(36) NOT NULL,
    create_request_sha256 VARCHAR(64) NOT NULL,
    create_request_canonical_json TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_openid4vp_client_id_prefix CHECK (
        client_id_prefix IN (
            'redirect_uri', 'x509_san_dns', 'x509_hash'
        )
    ),
    CONSTRAINT ck_openid4vp_request_method CHECK (
        request_method IN (
            'url_query', 'request_uri_signed_get', 'request_uri_signed_post'
        )
    ),
    CONSTRAINT ck_openid4vp_response_mode CHECK (
        response_mode IN ('direct_post', 'direct_post.jwt')
    ),
    CONSTRAINT ck_openid4vp_wallet_endpoint CHECK (
        wallet_authorization_endpoint ~ '^https://'
    ),
    CONSTRAINT ck_openid4vp_request_object
        CHECK (jsonb_typeof(request) = 'object' AND request <> '{}'::jsonb),
    CONSTRAINT ck_openid4vp_expiry CHECK (expires_at > created_at),
    CONSTRAINT ck_openid4vp_result_shape CHECK (
        (completed_at IS NULL AND result_ciphertext IS NULL)
        OR (completed_at IS NOT NULL AND result_ciphertext IS NOT NULL)
    ),
    CONSTRAINT ck_openid4vp_create_request_shape CHECK (
        create_request_jti ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        AND create_request_sha256 ~ '^[0-9a-f]{64}$'
        AND create_request_canonical_json <> ''
        AND octet_length(create_request_canonical_json) <= 65536
    )
);

CREATE INDEX ix_openid4vp_transaction_expiry ON openid4vp_transactions (expires_at);
CREATE UNIQUE INDEX ux_openid4vp_create_request_jti
    ON openid4vp_transactions (tenant_id, create_request_jti);

CREATE FUNCTION nazo_openid4vp_cleanup_expired_transactions()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_transactions INTEGER := 0;
BEGIN
    WITH expired AS (
        SELECT id
        FROM openid4vp_transactions
        WHERE expires_at <= CURRENT_TIMESTAMP
        ORDER BY expires_at, id
        LIMIT 256
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM openid4vp_transactions AS target
    USING expired
    WHERE target.id = expired.id;
    GET DIAGNOSTICS deleted_transactions = ROW_COUNT;
    RETURN deleted_transactions;
END;
$$;

COMMENT ON COLUMN openid4vp_transactions.ephemeral_private_key_ciphertext IS
    'AEAD-encrypted per-request response-decryption key; plaintext is never persisted.';
COMMENT ON COLUMN openid4vp_transactions.result_ciphertext IS
    'AEAD-encrypted disclosed presentation result with short retention.';
COMMENT ON COLUMN openid4vp_transactions.create_request_jti IS
    'Caller-generated, tenant-bound management idempotency key for exact OpenID4VP create response recovery.';
COMMENT ON COLUMN openid4vp_transactions.create_request_canonical_json IS
    'Canonical normalized management request compared with its SHA-256 digest to prevent JTI aliasing.';
COMMENT ON COLUMN openid4vci_deferred_transactions.payload_ciphertext IS
    'AEAD-encrypted deferred credential dataset; plaintext claims are never persisted.';
