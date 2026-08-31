DO $$
BEGIN
    RAISE EXCEPTION 'downgrade refused: tenant runtime revisions are authoritative';
END;
$$;

