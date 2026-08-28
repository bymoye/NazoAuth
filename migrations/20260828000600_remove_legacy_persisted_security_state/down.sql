-- Reintroducing legacy ciphertext AAD, nullable refresh/client policy state,
-- plaintext TOTP, or inherited runtime policy would revive removed security
-- behavior. Restore a pre-migration database together with the old release.
DO $$
BEGIN
    RAISE EXCEPTION
        'downgrade refused: legacy persisted security state was permanently removed';
END
$$;
