DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM openid4vp_verification_issuance_jtis)
       OR EXISTS (
        SELECT 1 FROM openid4vp_transactions
        WHERE create_request_jti IS NOT NULL
           OR create_request_sha256 IS NOT NULL
           OR create_request_canonical_json IS NOT NULL
           OR verification_run_jti IS NOT NULL
           OR verification_artifact_sha256 IS NOT NULL
           OR verification_matrix_sha256 IS NOT NULL
           OR verification_suite_plan_id IS NOT NULL
           OR verification_suite_module_id IS NOT NULL
           OR verification_test_name IS NOT NULL
           OR verification_variant_sha256 IS NOT NULL
           OR verification_context_sha256 IS NOT NULL
           OR verification_intent_jws IS NOT NULL
           OR verification_presentation_request_sha256 IS NOT NULL
           OR verification_issuance_expires_at IS NOT NULL
           OR verification_receipt_id IS NOT NULL
           OR verification_issuance_request_jti IS NOT NULL
           OR verification_capability_sha256 IS NOT NULL
           OR verification_capability_ciphertext IS NOT NULL
           OR verification_receipt_jws IS NOT NULL
           OR verification_issued_at IS NOT NULL
           OR verification_expires_at IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'drain every OpenID4VP transaction/create idempotency binding, verification attachment, and receipt before rollback';
    END IF;
END
$$;

DROP FUNCTION IF EXISTS nazo_openid4vp_cleanup_expired_transactions();
DROP INDEX IF EXISTS ix_openid4vp_cleanup_deadline;
DROP INDEX IF EXISTS ix_openid4vp_verification_issuance_jtis_transaction;
DROP TABLE IF EXISTS openid4vp_verification_issuance_jtis;
DROP INDEX IF EXISTS ux_openid4vp_verification_issuance_request;
DROP INDEX IF EXISTS ux_openid4vp_verification_capability;
DROP INDEX IF EXISTS ux_openid4vp_verification_context;
DROP INDEX IF EXISTS ux_openid4vp_verification_receipt_id;
DROP INDEX IF EXISTS ux_openid4vp_create_request_jti;

ALTER TABLE openid4vp_transactions
    DROP CONSTRAINT IF EXISTS uq_openid4vp_transaction_tenant_id,
    DROP CONSTRAINT IF EXISTS ck_openid4vp_create_request_shape,
    DROP CONSTRAINT IF EXISTS ck_openid4vp_verification_context_shape,
    DROP CONSTRAINT IF EXISTS ck_openid4vp_verification_issuance_window,
    DROP CONSTRAINT IF EXISTS ck_openid4vp_verification_receipt_shape,
    DROP COLUMN IF EXISTS verification_expires_at,
    DROP COLUMN IF EXISTS verification_issued_at,
    DROP COLUMN IF EXISTS verification_receipt_jws,
    DROP COLUMN IF EXISTS verification_capability_ciphertext,
    DROP COLUMN IF EXISTS verification_capability_sha256,
    DROP COLUMN IF EXISTS verification_issuance_request_jti,
    DROP COLUMN IF EXISTS verification_issuance_expires_at,
    DROP COLUMN IF EXISTS verification_presentation_request_sha256,
    DROP COLUMN IF EXISTS verification_intent_jws,
    DROP COLUMN IF EXISTS verification_context_sha256,
    DROP COLUMN IF EXISTS verification_variant_sha256,
    DROP COLUMN IF EXISTS verification_test_name,
    DROP COLUMN IF EXISTS verification_suite_module_id,
    DROP COLUMN IF EXISTS verification_suite_plan_id,
    DROP COLUMN IF EXISTS verification_matrix_sha256,
    DROP COLUMN IF EXISTS verification_artifact_sha256,
    DROP COLUMN IF EXISTS verification_run_jti,
    DROP COLUMN IF EXISTS verification_receipt_id,
    DROP COLUMN IF EXISTS create_request_canonical_json,
    DROP COLUMN IF EXISTS create_request_sha256,
    DROP COLUMN IF EXISTS create_request_jti;
