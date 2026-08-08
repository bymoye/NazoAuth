ALTER TABLE conformance_leases
    ADD COLUMN ciba_decision_claim_id UUID,
    ADD COLUMN ciba_decision_claim_expires_at TIMESTAMPTZ;

ALTER TABLE conformance_leases
    ADD CONSTRAINT conformance_leases_ciba_decision_claim_pair_check
    CHECK ((ciba_decision_claim_id IS NULL) = (ciba_decision_claim_expires_at IS NULL));

COMMENT ON COLUMN conformance_leases.ciba_decision_claim_id IS
    'Short-lived owner claim for a CIBA decision callback; never held across a database callback connection.';

COMMENT ON COLUMN conformance_leases.ciba_decision_claim_expires_at IS
    'Bounded deadline after which an abandoned CIBA decision claim may be reclaimed.';
