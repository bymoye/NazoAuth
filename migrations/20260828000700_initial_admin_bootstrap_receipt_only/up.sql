-- Bootstrap authority lives in the runtime-owned token file and deployment
-- identity. PostgreSQL stores only the committed idempotency receipt.
DELETE FROM initial_admin_bootstrap
WHERE consumed_at IS NULL
   OR request_id IS NULL
   OR request_email_hash IS NULL
   OR claimed_user_id IS NULL
   OR claim_result <> 'created'
   OR receipt_version <> 1
   OR claimed_at IS NULL;

UPDATE initial_admin_bootstrap
SET created_at = claimed_at;

ALTER TABLE initial_admin_bootstrap
    DROP CONSTRAINT ck_initial_admin_bootstrap_expiry,
    DROP CONSTRAINT ck_initial_admin_bootstrap_closed_receipt,
    DROP CONSTRAINT ck_initial_admin_bootstrap_claim_result,
    DROP CONSTRAINT ck_initial_admin_bootstrap_receipt_version,
    DROP COLUMN expires_at,
    DROP COLUMN consumed_at,
    DROP COLUMN claim_result,
    DROP COLUMN receipt_version,
    DROP COLUMN claimed_at,
    DROP COLUMN updated_at,
    ALTER COLUMN request_id SET NOT NULL,
    ALTER COLUMN request_email_hash SET NOT NULL,
    ALTER COLUMN claimed_user_id SET NOT NULL;

ALTER TABLE initial_admin_bootstrap
    RENAME TO initial_admin_bootstrap_receipts;

ALTER TABLE initial_admin_bootstrap_receipts
    RENAME CONSTRAINT initial_admin_bootstrap_pkey
        TO initial_admin_bootstrap_receipts_pkey;
ALTER TABLE initial_admin_bootstrap_receipts
    RENAME CONSTRAINT ck_initial_admin_bootstrap_singleton
        TO ck_initial_admin_bootstrap_receipts_singleton;
ALTER TABLE initial_admin_bootstrap_receipts
    RENAME CONSTRAINT ck_initial_admin_bootstrap_token_hash_length
        TO ck_initial_admin_bootstrap_receipts_token_hash_length;
ALTER TABLE initial_admin_bootstrap_receipts
    RENAME CONSTRAINT ck_initial_admin_bootstrap_request_id
        TO ck_initial_admin_bootstrap_receipts_request_id;
ALTER TABLE initial_admin_bootstrap_receipts
    RENAME CONSTRAINT ck_initial_admin_bootstrap_email_hash
        TO ck_initial_admin_bootstrap_receipts_email_hash;
ALTER TABLE initial_admin_bootstrap_receipts
    RENAME CONSTRAINT uq_initial_admin_bootstrap_request_id
        TO uq_initial_admin_bootstrap_receipts_request_id;
ALTER TABLE initial_admin_bootstrap_receipts
    RENAME CONSTRAINT uq_initial_admin_bootstrap_claimed_user
        TO uq_initial_admin_bootstrap_receipts_claimed_user;
ALTER TABLE initial_admin_bootstrap_receipts
    RENAME CONSTRAINT initial_admin_bootstrap_claimed_user_id_fkey
        TO initial_admin_bootstrap_receipts_claimed_user_id_fkey;

COMMENT ON TABLE initial_admin_bootstrap_receipts IS
    'Committed receipt for the single successful initial administrator claim; bootstrap authority remains in private runtime state.';
