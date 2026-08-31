CREATE TABLE openid4vci_pre_authorized_code_consumptions (
    offer_id UUID NOT NULL REFERENCES openid4vci_offers(id) ON DELETE CASCADE,
    client_id VARCHAR(255) NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (offer_id, client_id),
    CONSTRAINT ck_openid4vci_preauth_consumption_client_id
        CHECK (char_length(btrim(client_id)) BETWEEN 1 AND 255)
);

CREATE INDEX ix_openid4vci_preauth_consumption_consumed_at
    ON openid4vci_pre_authorized_code_consumptions (consumed_at);

COMMENT ON TABLE openid4vci_pre_authorized_code_consumptions IS
    'Per-client consumption receipts for OpenID4VCI pre-authorized codes; preserves replay protection across independent clients.';
