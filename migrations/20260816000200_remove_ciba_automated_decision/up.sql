-- CIBA itself remains a production protocol.  This migration removes only
-- the controller-injected automated-decision capability, which is owned by
-- the external conformance controller rather than the authorization server.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM ciba_decision_bindings) THEN
        RAISE EXCEPTION
            'cannot remove CIBA automated-decision bindings while rows remain; archive and purge them first'
            USING ERRCODE = '55006';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM tenant_resource_bindings
        WHERE resource_kind = 'ciba-decision-binding'
    ) THEN
        RAISE EXCEPTION
            'cannot remove CIBA automated-decision bindings while tenant resource binding rows remain; archive and purge them first'
            USING ERRCODE = '55006';
    END IF;
END;
$$;

DROP TABLE ciba_decision_bindings;

ALTER TABLE tenant_resource_bindings
    DROP CONSTRAINT IF EXISTS ck_tenant_resource_binding_kind;
ALTER TABLE tenant_resource_bindings
    ADD CONSTRAINT ck_tenant_resource_binding_kind CHECK (
        resource_kind IN (
            'oauth-client', 'mtls-trust-anchor', 'openid4vc-dataset',
            'openid4vc-trust-policy', 'user'
        )
    );
