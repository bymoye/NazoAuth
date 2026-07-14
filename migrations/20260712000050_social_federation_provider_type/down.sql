ALTER TABLE external_identity_links
    DROP CONSTRAINT ck_external_identity_links_provider_type;

ALTER TABLE external_identity_links
    ADD CONSTRAINT ck_external_identity_links_provider_type
    CHECK (provider_type IN ('oidc', 'saml'));
