ALTER TABLE openid4vp_transactions
    ADD COLUMN verification_receipt_id UUID,
    ADD COLUMN verification_run_jti VARCHAR(128),
    ADD COLUMN verification_artifact_sha256 VARCHAR(64),
    ADD COLUMN verification_matrix_sha256 VARCHAR(64),
    ADD COLUMN verification_suite_plan_id UUID,
    ADD COLUMN verification_suite_module_id UUID,
    ADD COLUMN verification_test_name VARCHAR(256),
    ADD COLUMN verification_variant_sha256 VARCHAR(64),
    ADD COLUMN verification_context_sha256 VARCHAR(64),
    ADD COLUMN verification_intent_jws TEXT,
    ADD COLUMN verification_presentation_request_sha256 VARCHAR(64),
    ADD COLUMN verification_issuance_expires_at TIMESTAMPTZ,
    ADD COLUMN verification_issuance_request_jti VARCHAR(36),
    ADD COLUMN verification_capability_sha256 VARCHAR(64),
    ADD COLUMN verification_capability_ciphertext BYTEA,
    ADD COLUMN verification_receipt_jws TEXT,
    ADD COLUMN verification_issued_at TIMESTAMPTZ,
    ADD COLUMN verification_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_openid4vp_verification_context_shape CHECK (
        (
            verification_run_jti IS NULL
            AND verification_artifact_sha256 IS NULL
            AND verification_matrix_sha256 IS NULL
            AND verification_suite_plan_id IS NULL
            AND verification_suite_module_id IS NULL
            AND verification_test_name IS NULL
            AND verification_variant_sha256 IS NULL
            AND verification_context_sha256 IS NULL
            AND verification_intent_jws IS NULL
            AND verification_presentation_request_sha256 IS NULL
        )
        OR (
            verification_run_jti IS NOT NULL
            AND verification_artifact_sha256 ~ '^[0-9a-f]{64}$'
            AND verification_matrix_sha256 ~ '^[0-9a-f]{64}$'
            AND verification_suite_plan_id IS NOT NULL
            AND verification_suite_module_id IS NOT NULL
            AND verification_test_name IS NOT NULL
            AND verification_test_name <> ''
            AND verification_variant_sha256 ~ '^[0-9a-f]{64}$'
            AND verification_context_sha256 ~ '^[0-9a-f]{64}$'
            AND verification_intent_jws IS NOT NULL
            AND verification_intent_jws <> ''
            AND octet_length(verification_intent_jws) <= 65536
            AND verification_presentation_request_sha256 ~ '^[0-9a-f]{64}$'
        )
    ),
    ADD CONSTRAINT ck_openid4vp_verification_issuance_window CHECK (
        verification_issuance_expires_at IS NULL
        OR (
            verification_context_sha256 IS NOT NULL
            AND verification_intent_jws IS NOT NULL
            AND verification_presentation_request_sha256 IS NOT NULL
            AND completed_at IS NOT NULL
            AND result_ciphertext IS NOT NULL
            AND verification_issuance_expires_at > completed_at
            AND verification_issuance_expires_at <= completed_at + INTERVAL '600 seconds'
        )
    ),
    ADD CONSTRAINT ck_openid4vp_verification_receipt_shape CHECK (
        (
            verification_receipt_id IS NULL
            AND verification_issuance_request_jti IS NULL
            AND verification_capability_sha256 IS NULL
            AND verification_capability_ciphertext IS NULL
            AND verification_receipt_jws IS NULL
            AND verification_issued_at IS NULL
            AND verification_expires_at IS NULL
        )
        OR (
            verification_receipt_id IS NOT NULL
            AND verification_issuance_request_jti ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            AND verification_capability_sha256 ~ '^[0-9a-f]{64}$'
            AND verification_capability_ciphertext IS NOT NULL
            AND octet_length(verification_capability_ciphertext) > 28
            AND verification_receipt_jws IS NOT NULL
            AND verification_receipt_jws <> ''
            AND octet_length(verification_receipt_jws) <= 65536
            AND verification_issued_at IS NOT NULL
            AND verification_expires_at IS NOT NULL
            AND verification_context_sha256 IS NOT NULL
            AND verification_intent_jws IS NOT NULL
            AND verification_presentation_request_sha256 IS NOT NULL
            AND verification_issuance_expires_at IS NOT NULL
            AND completed_at IS NOT NULL
            AND result_ciphertext IS NOT NULL
            AND verification_expires_at > verification_issued_at
            AND verification_expires_at <= verification_issued_at + INTERVAL '600 seconds'
        )
    );

CREATE UNIQUE INDEX ux_openid4vp_verification_receipt_id
    ON openid4vp_transactions (verification_receipt_id)
    WHERE verification_receipt_id IS NOT NULL;

CREATE UNIQUE INDEX ux_openid4vp_verification_context
    ON openid4vp_transactions (tenant_id, verification_context_sha256)
    WHERE verification_context_sha256 IS NOT NULL;

CREATE UNIQUE INDEX ux_openid4vp_verification_capability
    ON openid4vp_transactions (verification_capability_sha256)
    WHERE verification_capability_sha256 IS NOT NULL;

CREATE UNIQUE INDEX ux_openid4vp_verification_issuance_request
    ON openid4vp_transactions (tenant_id, verification_issuance_request_jti)
    WHERE verification_issuance_request_jti IS NOT NULL;

CREATE TABLE openid4vp_verification_issuance_jtis (
    tenant_id UUID NOT NULL,
    transaction_id UUID NOT NULL REFERENCES openid4vp_transactions(id) ON DELETE CASCADE,
    issuance_request_jti VARCHAR(36) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, issuance_request_jti),
    CONSTRAINT ck_openid4vp_verification_issuance_jti_shape CHECK (
        issuance_request_jti ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
);

CREATE INDEX ix_openid4vp_verification_issuance_jtis_transaction
    ON openid4vp_verification_issuance_jtis (transaction_id);

CREATE FUNCTION nazo_openid4vp_cleanup_expired_transactions()
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_transactions INTEGER := 0;
BEGIN
    DELETE FROM openid4vp_transactions
    WHERE GREATEST(
        expires_at,
        COALESCE(verification_issuance_expires_at, expires_at),
        COALESCE(verification_expires_at, expires_at)
    ) <= CURRENT_TIMESTAMP;
    GET DIAGNOSTICS deleted_transactions = ROW_COUNT;
    RETURN deleted_transactions;
END;
$$;

COMMENT ON COLUMN openid4vp_transactions.verification_capability_sha256 IS
    'Domain-separated SHA-256 binding of the active post-verification capability; plaintext is retained only as short-lived AEAD ciphertext for same-JTI issuance retries.';
COMMENT ON COLUMN openid4vp_transactions.verification_intent_jws IS
    'Immutable instance-signed binding attached while pending: tenant, transaction, runtime identity, evidence context, presentation request digest, and exact trust-policy version fence.';
COMMENT ON COLUMN openid4vp_transactions.verification_issuance_expires_at IS
    'Independent post-completion issuance deadline, at most 600 seconds after successful completion.';
COMMENT ON COLUMN openid4vp_transactions.verification_receipt_jws IS
    'Current instance-signed successful verification receipt, atomically replaced only by a distinct issuance request JTI.';
COMMENT ON COLUMN openid4vp_transactions.verification_expires_at IS
    'Short-lived public receipt expiry, at most 600 seconds from capability issuance and independent of the original transaction expiry after completion.';
COMMENT ON COLUMN openid4vp_transactions.verification_context_sha256 IS
    'Canonical SHA-256 binding of the external run, artifact, matrix, plan, module, test, and variant context.';
COMMENT ON TABLE openid4vp_verification_issuance_jtis IS
    'Tenant-bound durable used-JTI fence. The current JTI replays exactly; a superseded JTI cannot be reused to rotate again and is removed only with its transaction.';
