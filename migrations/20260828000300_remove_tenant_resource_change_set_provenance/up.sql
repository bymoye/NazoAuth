-- The historical model admitted multiple inactive provenance rows per
-- resource identity. A hard cut must choose one real binding before making
-- identity unique; it must never silently choose between two active rows.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM tenant_resource_bindings
        GROUP BY tenant_id, resource_kind, resource_id
        HAVING count(*) FILTER (WHERE active) > 1
    ) THEN
        RAISE EXCEPTION
            'tenant_resource_bindings contains multiple active rows for one identity';
    END IF;
END;
$$;

WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY tenant_id, resource_kind, resource_id
               ORDER BY active DESC, updated_at DESC, created_at DESC, id DESC
           ) AS ordinal
    FROM tenant_resource_bindings
)
DELETE FROM tenant_resource_bindings
WHERE id IN (SELECT id FROM ranked WHERE ordinal > 1);

ALTER TABLE tenant_resource_bindings
    DROP CONSTRAINT uq_tenant_resource_binding_version,
    DROP CONSTRAINT ck_tenant_resource_binding_change_set,
    DROP COLUMN change_set_id,
    DROP COLUMN change_set_sha256;

DROP INDEX uq_tenant_resource_binding_active;

ALTER TABLE tenant_resource_bindings
    ADD CONSTRAINT uq_tenant_resource_binding_identity
        UNIQUE (tenant_id, resource_kind, resource_id);
