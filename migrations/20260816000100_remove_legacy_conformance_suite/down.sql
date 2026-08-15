-- This migration irreversibly removes retired conformance evidence and schema.
-- Recreating lease tables without their historical receipts would fabricate a
-- rollback state, so deployment rollback must use a database backup instead.
DO $$
BEGIN
    RAISE EXCEPTION 'legacy conformance-suite removal cannot be rolled back without a database backup'
        USING ERRCODE = '55006';
END;
$$;
