-- The hard cut replaces the historical tenant-resource operation model and
-- deliberately discards data that cannot be reconstructed. Rolling this
-- migration back would leave Diesel's migration ledger claiming the old
-- schema while its table is absent. Recovery therefore requires restoring a
-- pre-cut database snapshot instead of manufacturing a half-old schema.
DO $$
BEGIN
    RAISE EXCEPTION
        'downgrade refused: tenant-resource replay hard cut requires database restore';
END;
$$;
