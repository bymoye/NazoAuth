DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM user_totp_credentials
        WHERE secret_base32 IS NULL
           OR secret_ciphertext IS NOT NULL
           OR secret_key_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'cannot roll back TOTP envelope migration after plaintext has been cleared';
    END IF;

    ALTER TABLE user_totp_credentials
        DROP CONSTRAINT ck_user_totp_credentials_secret_envelope,
        DROP COLUMN secret_ciphertext,
        DROP COLUMN secret_key_id,
        ALTER COLUMN secret_base32 SET NOT NULL;

    ALTER TABLE user_totp_credentials
        ADD CONSTRAINT ck_user_totp_credentials_secret_non_empty
        CHECK (length(trim(secret_base32)) >= 16);
END
$$;
