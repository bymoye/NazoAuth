ALTER TABLE oauth_tokens
    DROP COLUMN IF EXISTS oidc_auth_context;
