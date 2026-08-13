DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM conformance_leases
        WHERE suite_origin IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot roll back suite-origin binding while origin-bound leases remain';
    END IF;
END;
$$;

DROP INDEX IF EXISTS ix_conformance_leases_tenant_suite_origin;

ALTER TABLE conformance_leases
    DROP CONSTRAINT IF EXISTS ck_conformance_lease_suite_origin,
    DROP COLUMN IF EXISTS suite_origin;
