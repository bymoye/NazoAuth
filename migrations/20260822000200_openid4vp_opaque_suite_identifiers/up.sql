ALTER TABLE openid4vp_transactions
    ALTER COLUMN verification_suite_plan_id TYPE VARCHAR(128)
        USING verification_suite_plan_id::TEXT,
    ALTER COLUMN verification_suite_module_id TYPE VARCHAR(128)
        USING verification_suite_module_id::TEXT,
    ADD CONSTRAINT ck_openid4vp_verification_suite_identifiers CHECK (
        (
            verification_suite_plan_id IS NULL
            OR verification_suite_plan_id ~ '^[A-Za-z0-9._:+-]{1,128}$'
        )
        AND (
            verification_suite_module_id IS NULL
            OR verification_suite_module_id ~ '^[A-Za-z0-9._:+-]{1,128}$'
        )
    );

COMMENT ON COLUMN openid4vp_transactions.verification_suite_plan_id IS
    'Opaque, file-safe suite plan identifier bound into the signed verification evidence context; at most 128 ASCII bytes.';
COMMENT ON COLUMN openid4vp_transactions.verification_suite_module_id IS
    'Opaque, file-safe suite module identifier bound into the signed verification evidence context; at most 128 ASCII bytes.';
