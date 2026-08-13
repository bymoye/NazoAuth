-- TOTP seeds are decryptable credentials, not password-like values: they
-- cannot be replaced with a hash.  Keep the old column only long enough for
-- the explicit application migration to encrypt each row and clear it.
ALTER TABLE user_totp_credentials
    ALTER COLUMN secret_base32 DROP NOT NULL,
    ADD COLUMN secret_ciphertext BYTEA,
    ADD COLUMN secret_key_id VARCHAR(128);

ALTER TABLE user_totp_credentials
    DROP CONSTRAINT ck_user_totp_credentials_secret_non_empty,
    ADD CONSTRAINT ck_user_totp_credentials_secret_envelope CHECK (
        (
            secret_base32 IS NOT NULL
            AND secret_ciphertext IS NULL
            AND secret_key_id IS NULL
            AND length(trim(secret_base32)) >= 16
        )
        OR (
            secret_base32 IS NULL
            AND secret_ciphertext IS NOT NULL
            AND octet_length(secret_ciphertext) >= 30
            AND secret_key_id IS NOT NULL
            AND length(trim(secret_key_id)) > 0
        )
    );
