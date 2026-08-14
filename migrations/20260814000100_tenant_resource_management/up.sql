-- Ordinary tenant-resource management is a control-plane capability.  It is
-- deliberately independent from the conformance-suite provenance used by
-- the older onboarding path.
ALTER TABLE oauth_client_mtls_trust_anchor_requests
    ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE oauth_client_mtls_trust_anchor_requests
    DROP CONSTRAINT IF EXISTS ck_mtls_trust_anchor_source,
    DROP CONSTRAINT IF EXISTS ck_mtls_trust_anchor_state;

ALTER TABLE oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT ck_mtls_trust_anchor_source CHECK (
        source IN ('admin-session', 'operator-conformance', 'operator-managed')
    ),
    ADD CONSTRAINT ck_mtls_trust_anchor_state CHECK (
        (status = 0 AND source IN ('admin-session', 'operator-conformance')
            AND user_id IS NOT NULL AND resolved_by_user_id IS NULL AND resolved_at IS NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 0 AND source = 'operator-managed'
            AND user_id IS NULL AND resolved_by_user_id IS NULL AND resolved_at IS NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status IN (1, 2) AND source = 'admin-session'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 1 AND source = 'operator-conformance'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status IN (1, 2) AND source = 'operator-managed'
            AND user_id IS NULL AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 3 AND source = 'admin-session'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL)
        OR (status = 3 AND source = 'operator-conformance'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL)
        OR (status = 3 AND source = 'operator-managed'
            AND user_id IS NULL AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NOT NULL)
    );

-- Existing mTLS event rows intentionally keep provenance on their request.
-- The trigger makes the source/actor closure explicit without introducing a
-- second, independently mutable source column on the append-only event.
CREATE OR REPLACE FUNCTION nazo_oauth_validate_mtls_trust_event_actor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    request_source VARCHAR(32);
BEGIN
    SELECT source INTO request_source
    FROM oauth_client_mtls_trust_anchor_requests
    WHERE tenant_id = NEW.tenant_id AND id = NEW.request_id;
    IF request_source IS NULL THEN
        RAISE EXCEPTION 'mTLS trust event request does not exist'
            USING ERRCODE = '23503';
    END IF;
    IF request_source = 'admin-session' AND NEW.actor_user_id IS NULL THEN
        RAISE EXCEPTION 'admin-session trust events require an actor'
            USING ERRCODE = '23514';
    END IF;
    IF request_source = 'operator-conformance'
       AND (
           (NEW.action IN (0, 1) AND NEW.actor_user_id IS NOT NULL)
           OR (NEW.action = 3 AND NEW.actor_user_id IS NULL)
           OR NEW.action = 2
       ) THEN
        RAISE EXCEPTION 'operator-conformance trust event actor/action is inconsistent'
            USING ERRCODE = '23514';
    END IF;
    IF request_source = 'operator-managed' AND NEW.actor_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'operator-managed trust events cannot carry a user actor'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

ALTER TABLE openid4vci_credential_dataset_events
    DROP CONSTRAINT IF EXISTS ck_openid4vci_dataset_event_source;

ALTER TABLE openid4vci_credential_dataset_events
    ADD CONSTRAINT ck_openid4vci_dataset_event_source
    CHECK (source IN ('admin-session', 'operator-conformance', 'operator-managed'));

ALTER TABLE openid4vci_credential_dataset_events
    ALTER COLUMN actor_user_id DROP NOT NULL;

CREATE OR REPLACE FUNCTION nazo_oauth_validate_openid4vci_dataset_event_actor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.source IN ('admin-session', 'operator-conformance')
       AND NEW.actor_user_id IS NULL THEN
        RAISE EXCEPTION '% dataset events require a user actor', NEW.source
            USING ERRCODE = '23514';
    END IF;
    IF NEW.source = 'operator-managed' AND NEW.actor_user_id IS NOT NULL THEN
        RAISE EXCEPTION 'operator-managed dataset events cannot carry a user actor'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_openid4vci_dataset_event_actor
    ON openid4vci_credential_dataset_events;
CREATE TRIGGER trg_openid4vci_dataset_event_actor
BEFORE INSERT OR UPDATE ON openid4vci_credential_dataset_events
FOR EACH ROW
EXECUTE FUNCTION nazo_oauth_validate_openid4vci_dataset_event_actor();

CREATE TABLE tenant_resource_states (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    revision BIGINT NOT NULL DEFAULT 0,
    resource_manifest_sha256 VARCHAR(64) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_tenant_resource_state_revision CHECK (revision >= 0),
    CONSTRAINT ck_tenant_resource_state_manifest_sha256 CHECK (
        resource_manifest_sha256 ~ '^[0-9a-f]{64}$'
    )
);

CREATE TABLE tenant_resource_operations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    deployment_id VARCHAR(255) NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    jti VARCHAR(255) NOT NULL,
    change_set_id VARCHAR(255) NOT NULL,
    change_set_sha256 VARCHAR(64) NOT NULL,
    request_sha256 VARCHAR(64) NOT NULL,
    operation VARCHAR(32) NOT NULL,
    expected_revision BIGINT NOT NULL,
    result_revision BIGINT NOT NULL,
    receipt_json JSONB NOT NULL,
    receipt_jws TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_tenant_resource_operation_identity
        UNIQUE (deployment_id, tenant_id, jti),
    CONSTRAINT uq_tenant_resource_operation_change_set
        UNIQUE (deployment_id, tenant_id, change_set_id),
    CONSTRAINT ck_tenant_resource_operation_deployment CHECK (
        char_length(btrim(deployment_id)) BETWEEN 1 AND 255
        AND deployment_id = btrim(deployment_id)
    ),
    CONSTRAINT ck_tenant_resource_operation_jti CHECK (
        char_length(btrim(jti)) BETWEEN 1 AND 255
        AND jti = btrim(jti)
    ),
    CONSTRAINT ck_tenant_resource_operation_change_set_id CHECK (
        char_length(btrim(change_set_id)) BETWEEN 1 AND 255
        AND change_set_id = btrim(change_set_id)
    ),
    CONSTRAINT ck_tenant_resource_operation_change_set_sha256 CHECK (
        change_set_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_tenant_resource_operation_request_sha256 CHECK (
        request_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_tenant_resource_operation_name CHECK (
        operation IN ('apply', 'enumerate', 'revoke')
    ),
    CONSTRAINT ck_tenant_resource_operation_revisions CHECK (
        expected_revision >= 0
        AND result_revision >= 0
        AND CASE
            WHEN operation = 'enumerate' THEN result_revision = expected_revision
            WHEN operation IN ('apply', 'revoke') THEN
                expected_revision < 9223372036854775807
                AND result_revision::numeric = expected_revision::numeric + 1
            ELSE FALSE
        END
    ),
    CONSTRAINT ck_tenant_resource_operation_receipt_jws CHECK (
        receipt_jws = btrim(receipt_jws)
        AND octet_length(convert_to(receipt_jws, 'UTF8')) BETWEEN 1 AND 65536
    ),
    CONSTRAINT ck_tenant_resource_operation_receipt_json CHECK (
        jsonb_typeof(receipt_json) = 'object'
        AND octet_length(convert_to(receipt_json::text, 'UTF8')) <= 1048576
    )
);

CREATE INDEX ix_tenant_resource_operations_tenant_created
    ON tenant_resource_operations (tenant_id, created_at DESC, id);

CREATE FUNCTION nazo_tenant_resource_operations_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'tenant resource operation receipts are append-only'
        USING ERRCODE = '55006';
END;
$$;

CREATE TRIGGER trg_tenant_resource_operations_append_only
BEFORE UPDATE OR DELETE ON tenant_resource_operations
FOR EACH ROW
EXECUTE FUNCTION nazo_tenant_resource_operations_append_only();

CREATE TABLE tenant_resource_bindings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    resource_kind VARCHAR(64) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_digest VARCHAR(64) NOT NULL,
    change_set_id VARCHAR(255) NOT NULL,
    change_set_sha256 VARCHAR(64) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    locator TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_tenant_resource_binding_version
        UNIQUE (tenant_id, resource_kind, resource_id, change_set_id),
    CONSTRAINT ck_tenant_resource_binding_kind CHECK (
        resource_kind IN ('oauth-client', 'mtls-trust-anchor', 'openid4vc-dataset', 'user')
    ),
    CONSTRAINT ck_tenant_resource_binding_id CHECK (
        char_length(btrim(resource_id)) BETWEEN 1 AND 255
        AND resource_id = btrim(resource_id)
    ),
    CONSTRAINT ck_tenant_resource_binding_digest CHECK (
        resource_digest ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_tenant_resource_binding_change_set CHECK (
        char_length(btrim(change_set_id)) BETWEEN 1 AND 255
        AND change_set_id = btrim(change_set_id)
        AND change_set_sha256 ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT ck_tenant_resource_binding_locator CHECK (
        char_length(btrim(locator)) BETWEEN 1 AND 2048
    )
);

CREATE UNIQUE INDEX uq_tenant_resource_binding_active
    ON tenant_resource_bindings (tenant_id, resource_kind, resource_id)
    WHERE active;

CREATE INDEX ix_tenant_resource_bindings_tenant_kind
    ON tenant_resource_bindings (tenant_id, resource_kind, active, updated_at DESC);

CREATE FUNCTION nazo_guard_active_tenant_resource_owner()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    managed_kind VARCHAR(64);
    managed_locator TEXT;
BEGIN
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'users'
       AND (to_jsonb(OLD) - 'updated_at' - 'mfa_enabled')
           = (to_jsonb(NEW) - 'updated_at' - 'mfa_enabled') THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND TG_TABLE_NAME = 'oauth_clients'
       AND (to_jsonb(OLD) - 'updated_at') = (to_jsonb(NEW) - 'updated_at') THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'users' THEN
        managed_kind := 'user';
        managed_locator := 'user/' || OLD.id::text;
    ELSIF TG_TABLE_NAME = 'oauth_clients' THEN
        managed_kind := 'oauth-client';
        managed_locator := 'oauth-client/' || OLD.id::text;
    ELSE
        RAISE EXCEPTION 'tenant resource ownership guard attached to unsupported table'
            USING ERRCODE = '55006';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM tenant_resource_bindings binding
        WHERE binding.tenant_id = OLD.tenant_id
          AND binding.resource_kind = managed_kind
          AND binding.locator = managed_locator
          AND binding.active
    ) THEN
        RAISE EXCEPTION 'active tenant resource must be changed through its signed change set'
            USING ERRCODE = '55006';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER trg_users_active_tenant_resource_owner
BEFORE UPDATE OR DELETE ON users
FOR EACH ROW
EXECUTE FUNCTION nazo_guard_active_tenant_resource_owner();

CREATE TRIGGER trg_oauth_clients_active_tenant_resource_owner
BEFORE UPDATE OR DELETE ON oauth_clients
FOR EACH ROW
EXECUTE FUNCTION nazo_guard_active_tenant_resource_owner();

COMMENT ON TABLE tenant_resource_states IS
    'Authoritative tenant-scoped desired resource revision and canonical manifest digest.';
COMMENT ON TABLE tenant_resource_operations IS
    'Append-only tenant resource task idempotency and signed receipt evidence; replay compares request_sha256.';
COMMENT ON TABLE tenant_resource_bindings IS
    'Tenant-scoped resource identity/version bindings. Active rows are unique per typed resource identity.';
