-- CIBA itself remains a production protocol.  This migration removes only
-- the controller-injected automated-decision capability, which is owned by
-- the external conformance controller rather than the authorization server.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM ciba_decision_bindings
        WHERE active
    ) THEN
        RAISE EXCEPTION
            'cannot remove CIBA automated-decision bindings while active rows remain; revoke them through the controller first'
            USING ERRCODE = '55006';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM tenant_resource_bindings
        WHERE resource_kind = 'ciba-decision-binding'
          AND active
    ) THEN
        RAISE EXCEPTION
            'cannot remove CIBA automated-decision bindings while active tenant resource binding rows remain; revoke them through the controller first'
            USING ERRCODE = '55006';
    END IF;
END;
$$;

-- Inactive generations are immutable history.  Deployment retains an external
-- database backup before this irreversible cutover; no live protocol state
-- depends on these rows after the controller has revoked every active binding.
DELETE FROM ciba_decision_bindings
WHERE NOT active;

DELETE FROM tenant_resource_bindings
WHERE resource_kind = 'ciba-decision-binding'
  AND NOT active;

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
