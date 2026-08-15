DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM oauth_token_issuances WHERE user_id IS NOT NULL) THEN
        RAISE EXCEPTION
            'refusing to remove token issuance subject ownership while user-bound issuance evidence exists';
    END IF;
END;
$$;

DROP INDEX ix_oauth_token_issuances_tenant_user;

ALTER TABLE oauth_token_issuances
DROP CONSTRAINT fk_oauth_token_issuances_user_tenant,
DROP COLUMN user_id;
