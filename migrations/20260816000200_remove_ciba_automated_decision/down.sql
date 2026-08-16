-- This removal is intentionally forward-only. Reintroducing a controller
-- automated-decision capability would recreate a retired Suite-specific
-- authorization surface and cannot be safely inferred from historical rows.
DO $$
BEGIN
    RAISE EXCEPTION '20260816000200_remove_ciba_automated_decision is irreversible';
END;
$$;
