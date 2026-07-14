ALTER TABLE backchannel_logout_deliveries
    ADD COLUMN IF NOT EXISTS operation_key VARCHAR;

CREATE UNIQUE INDEX IF NOT EXISTS uq_backchannel_logout_operation_client
    ON backchannel_logout_deliveries (tenant_id, operation_key, client_id)
    WHERE operation_key IS NOT NULL;
