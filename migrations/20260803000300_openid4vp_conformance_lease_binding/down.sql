DROP TRIGGER IF EXISTS trg_conformance_leases_delete_presentations ON conformance_leases;
DROP FUNCTION IF EXISTS nazo_oauth_delete_revoked_conformance_presentations();

DROP TRIGGER IF EXISTS trg_openid4vp_transactions_conformance_lease ON openid4vp_transactions;
DROP FUNCTION IF EXISTS nazo_oauth_validate_conformance_presentation_lease_binding();
DROP INDEX IF EXISTS ix_openid4vp_transactions_conformance_lease;

ALTER TABLE openid4vp_transactions
    DROP CONSTRAINT IF EXISTS fk_openid4vp_transactions_conformance_lease,
    DROP COLUMN IF EXISTS conformance_lease_id;
