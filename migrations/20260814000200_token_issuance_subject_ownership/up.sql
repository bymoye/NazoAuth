ALTER TABLE oauth_token_issuances
ADD COLUMN user_id UUID;

ALTER TABLE oauth_token_issuances
ADD CONSTRAINT fk_oauth_token_issuances_user_tenant
FOREIGN KEY (user_id, tenant_id) REFERENCES users(id, tenant_id);

CREATE INDEX ix_oauth_token_issuances_tenant_user
ON oauth_token_issuances (tenant_id, user_id)
WHERE user_id IS NOT NULL;

COMMENT ON COLUMN oauth_token_issuances.user_id IS
    'Internal user ownership for tenant-scoped access-token revocation; NULL for subjectless grants.';
