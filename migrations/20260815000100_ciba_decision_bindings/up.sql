ALTER TABLE tenant_resource_bindings
    DROP CONSTRAINT ck_tenant_resource_binding_kind;

ALTER TABLE tenant_resource_bindings
    ADD CONSTRAINT ck_tenant_resource_binding_kind CHECK (
        resource_kind IN (
            'oauth-client', 'mtls-trust-anchor', 'ciba-decision-binding',
            'openid4vc-dataset', 'openid4vc-trust-policy', 'user'
        )
    );

CREATE TABLE ciba_decision_bindings (
    generation UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    resource_id VARCHAR(255) NOT NULL,
    resource_digest VARCHAR(64) NOT NULL,
    oauth_client_id UUID NOT NULL,
    user_id UUID NOT NULL,
    token_sha256 VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    decision_claim_id UUID,
    decision_claim_acquired_at TIMESTAMPTZ,
    decision_claim_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT fk_ciba_decision_binding_client_tenant
        FOREIGN KEY (oauth_client_id, tenant_id)
        REFERENCES oauth_clients(id, tenant_id),
    CONSTRAINT fk_ciba_decision_binding_user_tenant
        FOREIGN KEY (user_id, tenant_id)
        REFERENCES users(id, tenant_id),
    CONSTRAINT ck_ciba_decision_binding_resource_id CHECK (
        char_length(btrim(resource_id)) BETWEEN 1 AND 255
        AND resource_id = btrim(resource_id)
        AND resource_id !~ '[[:cntrl:]]'
    ),
    CONSTRAINT ck_ciba_decision_binding_resource_digest CHECK (
        resource_digest ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_ciba_decision_binding_token_sha256 CHECK (
        token_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_ciba_decision_binding_expiry CHECK (
        expires_at > created_at
    ),
    CONSTRAINT ck_ciba_decision_binding_active_state CHECK (
        (active AND revoked_at IS NULL)
        OR (NOT active AND revoked_at IS NOT NULL)
    ),
    CONSTRAINT ck_ciba_decision_binding_claim_state CHECK (
        (
            decision_claim_id IS NULL
            AND decision_claim_acquired_at IS NULL
            AND decision_claim_expires_at IS NULL
        ) OR (
            decision_claim_id IS NOT NULL
            AND decision_claim_acquired_at IS NOT NULL
            AND decision_claim_expires_at IS NOT NULL
            AND decision_claim_expires_at > decision_claim_acquired_at
            AND decision_claim_expires_at
                <= decision_claim_acquired_at + INTERVAL '30 seconds'
            AND decision_claim_expires_at <= expires_at
        )
    )
);

CREATE UNIQUE INDEX uq_ciba_decision_binding_active_resource
    ON ciba_decision_bindings (tenant_id, resource_id)
    WHERE active;

CREATE UNIQUE INDEX uq_ciba_decision_binding_active_token
    ON ciba_decision_bindings (tenant_id, token_sha256, oauth_client_id)
    WHERE active;

CREATE INDEX ix_ciba_decision_binding_active_client
    ON ciba_decision_bindings (tenant_id, oauth_client_id, expires_at)
    WHERE active;

CREATE INDEX ix_ciba_decision_binding_active_user
    ON ciba_decision_bindings (tenant_id, user_id, expires_at)
    WHERE active;

COMMENT ON TABLE ciba_decision_bindings IS
    'Ordinary tenant resource binding for bounded CIBA automated decisions; contains only token digests.';

COMMENT ON COLUMN ciba_decision_bindings.decision_claim_expires_at IS
    'Hard-bounded deadline used to linearize one automated decision against resource revoke.';
