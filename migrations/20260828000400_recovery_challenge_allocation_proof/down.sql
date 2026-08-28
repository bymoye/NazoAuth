-- Removing the allocation-proof boundary would make unauthenticated challenge
-- squatting possible again.  Roll back the release with a database restore;
-- never reinterpret proof-era state through the old request shape.
DO $$
BEGIN
    RAISE EXCEPTION
        'downgrade refused: Recovery Root allocation proof is mandatory';
END
$$;
