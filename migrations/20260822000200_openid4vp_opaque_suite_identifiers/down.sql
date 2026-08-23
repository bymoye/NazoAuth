DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM openid4vp_transactions
        WHERE (
            verification_suite_plan_id IS NOT NULL
            AND verification_suite_plan_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        ) OR (
            verification_suite_module_id IS NOT NULL
            AND verification_suite_module_id !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        )
    ) THEN
        RAISE EXCEPTION 'drain OpenID4VP verification contexts with opaque suite identifiers before rollback';
    END IF;
END
$$;

ALTER TABLE openid4vp_transactions
    DROP CONSTRAINT IF EXISTS ck_openid4vp_verification_suite_identifiers,
    ALTER COLUMN verification_suite_plan_id TYPE UUID
        USING verification_suite_plan_id::UUID,
    ALTER COLUMN verification_suite_module_id TYPE UUID
        USING verification_suite_module_id::UUID;

COMMENT ON COLUMN openid4vp_transactions.verification_suite_plan_id IS NULL;
COMMENT ON COLUMN openid4vp_transactions.verification_suite_module_id IS NULL;
