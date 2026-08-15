DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM tenant_resource_operations)
       OR EXISTS (SELECT 1 FROM tenant_resource_states)
       OR EXISTS (SELECT 1 FROM tenant_resource_bindings)
       OR EXISTS (SELECT 1 FROM openid4vc_trust_policies)
       OR EXISTS (SELECT 1 FROM openid4vc_trust_policy_clients)
       OR EXISTS (
           SELECT 1 FROM openid4vp_transactions
           WHERE openid4vc_trust_policy_binding_id IS NOT NULL
       ) THEN
        RAISE EXCEPTION
            'cannot roll back tenant resource management while state, binding, trust policy, or receipt rows remain';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM oauth_client_mtls_trust_anchor_requests
        WHERE source = 'operator-managed'
    ) OR EXISTS (
        SELECT 1
        FROM openid4vci_credential_dataset_events
        WHERE source = 'operator-managed'
    ) THEN
        RAISE EXCEPTION
            'cannot roll back tenant resource management while operator-managed rows remain';
    END IF;
END;
$$;

DROP TRIGGER IF EXISTS trg_openid4vci_dataset_event_actor
    ON openid4vci_credential_dataset_events;
DROP FUNCTION IF EXISTS nazo_oauth_validate_openid4vci_dataset_event_actor();
ALTER TABLE openid4vci_credential_dataset_events
    ALTER COLUMN actor_user_id SET NOT NULL;
ALTER TABLE openid4vci_credential_dataset_events
    DROP CONSTRAINT IF EXISTS ck_openid4vci_dataset_event_source;
ALTER TABLE openid4vci_credential_dataset_events
    ADD CONSTRAINT ck_openid4vci_dataset_event_source
    CHECK (source IN ('admin-session', 'operator-conformance'));

ALTER TABLE oauth_client_mtls_trust_anchor_requests
    DROP CONSTRAINT IF EXISTS ck_mtls_trust_anchor_source,
    DROP CONSTRAINT IF EXISTS ck_mtls_trust_anchor_state;
ALTER TABLE oauth_client_mtls_trust_anchor_requests
    ADD CONSTRAINT ck_mtls_trust_anchor_source CHECK (
        source IN ('admin-session', 'operator-conformance')
    ),
    ADD CONSTRAINT ck_mtls_trust_anchor_state CHECK (
        (status = 0 AND source IN ('admin-session', 'operator-conformance')
            AND user_id IS NOT NULL AND resolved_by_user_id IS NULL AND resolved_at IS NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status IN (1, 2) AND source = 'admin-session'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 1 AND source = 'operator-conformance'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NULL AND revoked_at IS NULL)
        OR (status = 3 AND source = 'admin-session'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NOT NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL)
        OR (status = 3 AND source = 'operator-conformance'
            AND user_id IS NOT NULL AND resolved_by_user_id IS NULL AND resolved_at IS NOT NULL
            AND revoked_by_user_id IS NOT NULL AND revoked_at IS NOT NULL)
    );

ALTER TABLE oauth_client_mtls_trust_anchor_requests
    ALTER COLUMN user_id SET NOT NULL;

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
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_tenant_resource_operations_append_only
    ON tenant_resource_operations;
DROP FUNCTION IF EXISTS nazo_tenant_resource_operations_append_only();
DROP TRIGGER IF EXISTS trg_users_active_tenant_resource_owner ON users;
DROP TRIGGER IF EXISTS trg_oauth_clients_active_tenant_resource_owner ON oauth_clients;
DROP FUNCTION IF EXISTS nazo_guard_active_tenant_resource_owner();
DROP TRIGGER IF EXISTS trg_openid4vp_transactions_trust_policy_binding
    ON openid4vp_transactions;
DROP FUNCTION IF EXISTS nazo_validate_openid4vp_trust_policy_binding();
DROP FUNCTION IF EXISTS openid4vc_presentation_trust_policy_is_active(UUID, UUID, VARCHAR, VARCHAR);
DROP INDEX IF EXISTS ix_openid4vp_transactions_openid4vc_trust_policy;
ALTER TABLE openid4vp_transactions
    DROP CONSTRAINT IF EXISTS fk_openid4vp_transactions_openid4vc_trust_policy,
    DROP CONSTRAINT IF EXISTS ck_openid4vp_transactions_trust_owner,
    DROP CONSTRAINT IF EXISTS ck_openid4vp_transactions_trust_policy_binding,
    DROP COLUMN IF EXISTS openid4vc_trust_policy_binding_id,
    DROP COLUMN IF EXISTS openid4vc_trust_policy_resource_id,
    DROP COLUMN IF EXISTS openid4vc_trust_policy_digest;
DROP TRIGGER IF EXISTS trg_openid4vc_trust_policy_client_generation
    ON openid4vc_trust_policy_clients;
DROP FUNCTION IF EXISTS nazo_guard_openid4vc_trust_policy_client_generation();
DROP TABLE IF EXISTS openid4vc_trust_policy_clients;
DROP TRIGGER IF EXISTS trg_openid4vc_trust_policy_generation
    ON openid4vc_trust_policies;
DROP FUNCTION IF EXISTS nazo_guard_openid4vc_trust_policy_generation();
DROP TABLE IF EXISTS openid4vc_trust_policies;
DROP FUNCTION IF EXISTS nazo_valid_openid4vc_wallet_origins(JSONB);
DROP INDEX IF EXISTS uq_oauth_clients_tenant_internal_id;
DROP TABLE IF EXISTS tenant_resource_bindings;
DROP TABLE IF EXISTS tenant_resource_operations;
DROP TABLE IF EXISTS tenant_resource_states;
