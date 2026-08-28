-- Dropping key history would make rotated-away Recovery Secrets valid again.
-- Restore a pre-migration database when rolling back the release.
DO $$
BEGIN
    RAISE EXCEPTION
        'downgrade refused: Recovery Root key history is mandatory';
END
$$;
