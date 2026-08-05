DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_token_issuances) THEN
        RAISE EXCEPTION
            'cannot roll back token issuance saga while durable issuance records exist';
    END IF;
END
$$;

DROP TABLE oauth_token_issuances;
