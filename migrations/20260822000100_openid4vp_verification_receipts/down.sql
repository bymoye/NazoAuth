DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM openid4vp_transactions
        WHERE verification_receipt_jws IS NOT NULL
          AND verification_expires_at > NOW()
    ) THEN
        RAISE EXCEPTION 'drain active OpenID4VP verification receipts before rollback';
    END IF;
END
$$;

DROP INDEX IF EXISTS ux_openid4vp_verification_capability;
DROP INDEX IF EXISTS ux_openid4vp_verification_context;
DROP INDEX IF EXISTS ux_openid4vp_verification_receipt_id;

ALTER TABLE openid4vp_transactions
    DROP CONSTRAINT IF EXISTS ck_openid4vp_verification_context_shape,
    DROP CONSTRAINT IF EXISTS ck_openid4vp_verification_receipt_shape,
    DROP COLUMN IF EXISTS verification_expires_at,
    DROP COLUMN IF EXISTS verification_issued_at,
    DROP COLUMN IF EXISTS verification_receipt_jws,
    DROP COLUMN IF EXISTS verification_capability_sha256,
    DROP COLUMN IF EXISTS verification_intent_jws,
    DROP COLUMN IF EXISTS verification_context_sha256,
    DROP COLUMN IF EXISTS verification_variant_sha256,
    DROP COLUMN IF EXISTS verification_test_name,
    DROP COLUMN IF EXISTS verification_suite_module_id,
    DROP COLUMN IF EXISTS verification_suite_plan_id,
    DROP COLUMN IF EXISTS verification_matrix_sha256,
    DROP COLUMN IF EXISTS verification_artifact_sha256,
    DROP COLUMN IF EXISTS verification_run_jti,
    DROP COLUMN IF EXISTS verification_receipt_id;
