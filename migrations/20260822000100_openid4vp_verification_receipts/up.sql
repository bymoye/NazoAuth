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
    ADD COLUMN verification_capability_sha256 VARCHAR(64),
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
        )
    ),
    ADD CONSTRAINT ck_openid4vp_verification_receipt_shape CHECK (
        (
            verification_receipt_id IS NULL
            AND verification_capability_sha256 IS NULL
            AND verification_receipt_jws IS NULL
            AND verification_issued_at IS NULL
            AND verification_expires_at IS NULL
        )
        OR (
            verification_receipt_id IS NOT NULL
            AND verification_capability_sha256 ~ '^[0-9a-f]{64}$'
            AND verification_receipt_jws IS NOT NULL
            AND verification_receipt_jws <> ''
            AND octet_length(verification_receipt_jws) <= 65536
            AND verification_issued_at IS NOT NULL
            AND verification_expires_at IS NOT NULL
            AND verification_context_sha256 IS NOT NULL
            AND completed_at IS NOT NULL
            AND result_ciphertext IS NOT NULL
            AND verification_expires_at > verification_issued_at
            AND verification_expires_at <= expires_at
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

COMMENT ON COLUMN openid4vp_transactions.verification_capability_sha256 IS
    'Domain-separated SHA-256 binding of the currently active post-verification capability; capability plaintext is returned once and never persisted.';
COMMENT ON COLUMN openid4vp_transactions.verification_intent_jws IS
    'Immutable instance-signed binding of tenant, transaction, runtime identity, and external evidence context created with the transaction.';
COMMENT ON COLUMN openid4vp_transactions.verification_receipt_jws IS
    'Current instance-signed successful verification receipt, atomically rotated with its capability hash and expiry.';
COMMENT ON COLUMN openid4vp_transactions.verification_expires_at IS
    'Short-lived public receipt expiry starting at capability issuance; never extends the presentation transaction lifetime.';
COMMENT ON COLUMN openid4vp_transactions.verification_context_sha256 IS
    'Canonical SHA-256 binding of the immutable external run, artifact, matrix, plan, module, test, and variant context.';
