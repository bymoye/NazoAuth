DO $$
BEGIN
    RAISE EXCEPTION
        '20260828000300 removes obsolete provenance data and is intentionally irreversible';
END;
$$;
