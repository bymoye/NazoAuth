DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'oauth_clients'
          AND column_name = 'client_secret_hash'
    ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'oauth_clients'
          AND column_name = 'client_secret_argon2_hash'
    ) THEN
        ALTER TABLE oauth_clients
            RENAME COLUMN client_secret_hash TO client_secret_argon2_hash;
    END IF;
END $$;
