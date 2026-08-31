CREATE OR REPLACE FUNCTION nazo_bump_tenant_runtime_directory_revision()
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
