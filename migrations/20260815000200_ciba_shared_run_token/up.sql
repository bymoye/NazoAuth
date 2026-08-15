DROP INDEX uq_ciba_decision_binding_active_token;

CREATE UNIQUE INDEX uq_ciba_decision_binding_active_token
    ON ciba_decision_bindings (tenant_id, token_sha256, oauth_client_id)
    WHERE active;
