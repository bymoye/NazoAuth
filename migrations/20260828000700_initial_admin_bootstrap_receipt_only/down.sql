DO $$
BEGIN
    RAISE EXCEPTION 'initial administrator bootstrap leases were removed intentionally and cannot be restored';
END
$$;
