CREATE TABLE tenant_runtime_directory_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    revision BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_tenant_runtime_directory_singleton CHECK (singleton),
    CONSTRAINT ck_tenant_runtime_directory_revision CHECK (revision >= 0)
);

INSERT INTO tenant_runtime_directory_state (singleton, revision)
VALUES (TRUE, 0);

CREATE TABLE tenant_runtime_bindings (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    realm_id UUID NOT NULL,
    organization_id UUID NOT NULL,
    issuer TEXT NOT NULL,
    external_host VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_tenant_runtime_binding_realm
        FOREIGN KEY (realm_id, tenant_id) REFERENCES realms(id, tenant_id),
    CONSTRAINT fk_tenant_runtime_binding_organization
        FOREIGN KEY (organization_id, tenant_id) REFERENCES organizations(id, tenant_id),
    CONSTRAINT ck_tenant_runtime_binding_issuer CHECK (
        char_length(btrim(issuer)) BETWEEN 1 AND 2048
        AND issuer = btrim(issuer)
    ),
    CONSTRAINT ck_tenant_runtime_binding_host CHECK (
        char_length(btrim(external_host)) BETWEEN 1 AND 255
        AND external_host = btrim(external_host)
        AND external_host = lower(external_host)
    ),
    CONSTRAINT uq_tenant_runtime_binding_issuer UNIQUE (issuer),
    CONSTRAINT uq_tenant_runtime_binding_host UNIQUE (external_host)
);

CREATE FUNCTION nazo_bump_tenant_runtime_directory_revision()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP <> 'TRUNCATE' AND TG_TABLE_NAME = 'tenants'
       AND NOT EXISTS (
           SELECT 1 FROM public.tenant_runtime_bindings WHERE tenant_id = NEW.id
       ) THEN
        RETURN NULL;
    END IF;
    IF TG_OP <> 'TRUNCATE' AND TG_TABLE_NAME = 'realms'
       AND NOT EXISTS (
           SELECT 1 FROM public.tenant_runtime_bindings WHERE realm_id = NEW.id
       ) THEN
        RETURN NULL;
    END IF;
    IF TG_OP <> 'TRUNCATE' AND TG_TABLE_NAME = 'organizations'
       AND NOT EXISTS (
           SELECT 1 FROM public.tenant_runtime_bindings WHERE organization_id = NEW.id
       ) THEN
        RETURN NULL;
    END IF;

    UPDATE public.tenant_runtime_directory_state
    SET revision = revision + 1,
        updated_at = CURRENT_TIMESTAMP
    WHERE singleton;
    RETURN NULL;
END;
$$;

REVOKE ALL ON FUNCTION nazo_bump_tenant_runtime_directory_revision() FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON tenant_runtime_directory_state FROM PUBLIC;

CREATE TRIGGER trg_tenant_runtime_bindings_revision
AFTER INSERT OR UPDATE OR DELETE ON tenant_runtime_bindings
FOR EACH ROW
EXECUTE FUNCTION nazo_bump_tenant_runtime_directory_revision();

CREATE TRIGGER trg_tenant_runtime_bindings_truncate_revision
AFTER TRUNCATE ON tenant_runtime_bindings
FOR EACH STATEMENT
EXECUTE FUNCTION nazo_bump_tenant_runtime_directory_revision();

CREATE TRIGGER trg_tenants_runtime_status_revision
AFTER UPDATE OF status ON tenants
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION nazo_bump_tenant_runtime_directory_revision();

CREATE TRIGGER trg_realms_runtime_status_revision
AFTER UPDATE OF status ON realms
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION nazo_bump_tenant_runtime_directory_revision();

CREATE TRIGGER trg_organizations_runtime_status_revision
AFTER UPDATE OF status ON organizations
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION nazo_bump_tenant_runtime_directory_revision();
