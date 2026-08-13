ALTER TABLE conformance_leases
    DROP CONSTRAINT IF EXISTS conformance_leases_ciba_decision_claim_pair_check;

ALTER TABLE conformance_leases
    DROP COLUMN IF EXISTS ciba_decision_claim_expires_at,
    DROP COLUMN IF EXISTS ciba_decision_claim_id;
