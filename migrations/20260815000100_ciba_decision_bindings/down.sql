DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM ciba_decision_bindings)
        OR EXISTS (
            SELECT 1
            FROM tenant_resource_bindings
            WHERE resource_kind = 'ciba-decision-binding'
        )
    THEN
        RAISE EXCEPTION
            'refusing to remove CIBA decision bindings while resource state exists';
    END IF;
END;
$$;

DROP TABLE ciba_decision_bindings;

ALTER TABLE tenant_resource_bindings
    DROP CONSTRAINT ck_tenant_resource_binding_kind;

ALTER TABLE tenant_resource_bindings
    ADD CONSTRAINT ck_tenant_resource_binding_kind CHECK (
        resource_kind IN (
            'oauth-client', 'mtls-trust-anchor', 'openid4vc-dataset',
            'openid4vc-trust-policy', 'user'
        )
    );
