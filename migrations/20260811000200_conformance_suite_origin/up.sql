-- Bind an atomic conformance lease to the exact OpenID Foundation Suite
-- origin used for the run. Legacy leases remain NULL and are intentionally
-- not eligible for the origin-scoped resolver.
ALTER TABLE conformance_leases
    ADD COLUMN suite_origin VARCHAR(2048),
    ADD CONSTRAINT ck_conformance_lease_suite_origin CHECK (
        suite_origin IS NULL
        OR (
            octet_length(suite_origin) BETWEEN 9 AND 2048
            AND suite_origin = btrim(suite_origin)
            AND suite_origin ~ '^https://[^/?#@]+$'
            AND suite_origin !~ '[[:cntrl:]]'
        )
    );

CREATE INDEX ix_conformance_leases_tenant_suite_origin
    ON conformance_leases (tenant_id, suite_origin, profile, expires_at, id)
    WHERE suite_origin IS NOT NULL;

COMMENT ON COLUMN conformance_leases.suite_origin IS
    'Canonical HTTPS origin of the conformance Suite for atomic nazoauth-full onboarding; NULL on legacy leases.';
