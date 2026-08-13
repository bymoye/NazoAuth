DROP INDEX IF EXISTS ix_openid4vci_deferred_claim_expiry;
DROP INDEX IF EXISTS ix_openid4vci_nonce_claim_expiry;
DROP TABLE IF EXISTS openid4vci_issuance_responses;

ALTER TABLE openid4vci_deferred_transactions
    DROP CONSTRAINT IF EXISTS ck_openid4vci_deferred_claim,
    DROP COLUMN IF EXISTS claim_expires_at,
    DROP COLUMN IF EXISTS claim_id;

ALTER TABLE openid4vci_nonces
    DROP CONSTRAINT IF EXISTS ck_openid4vci_nonce_claim,
    DROP COLUMN IF EXISTS claim_expires_at,
    DROP COLUMN IF EXISTS claim_id;
