ALTER TABLE oauth_tokens
    ADD COLUMN oidc_auth_context JSONB;

COMMENT ON COLUMN oauth_tokens.oidc_auth_context IS
    'Versioned OIDC authentication and claim contract used when issuing ID Tokens from refresh tokens; NULL denotes a legacy token with no recoverable contract.';
