DROP TRIGGER IF EXISTS trg_conformance_leases_clear_token_digests
    ON conformance_leases;
DROP FUNCTION IF EXISTS nazo_oauth_clear_conformance_lease_token_digests();
DROP INDEX IF EXISTS uq_conformance_lease_tenant_ciba_decision_token_sha256;
DROP INDEX IF EXISTS uq_conformance_lease_tenant_dcr_token_sha256;
ALTER TABLE conformance_leases
    DROP CONSTRAINT IF EXISTS ck_conformance_lease_dcr_token_sha256,
    DROP CONSTRAINT IF EXISTS ck_conformance_lease_ciba_decision_token_sha256,
    DROP COLUMN IF EXISTS dynamic_registration_initial_access_token_sha256,
    DROP COLUMN IF EXISTS ciba_automated_decision_token_sha256;
