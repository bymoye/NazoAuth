DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'oauth_clients'
          AND column_name = 'client_secret_argon2_hash'
    ) AND NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'oauth_clients'
          AND column_name = 'client_secret_hash'
    ) THEN
        ALTER TABLE oauth_clients
            RENAME COLUMN client_secret_argon2_hash TO client_secret_hash;
    ELSIF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'oauth_clients'
          AND column_name = 'client_secret_hash'
    ) THEN
        ALTER TABLE oauth_clients
            ADD COLUMN client_secret_hash VARCHAR(512);
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'oauth_clients'
          AND column_name = 'client_secret_argon2_hash'
    ) THEN
        ALTER TABLE oauth_clients
            DROP COLUMN client_secret_argon2_hash;
    END IF;
END $$;
