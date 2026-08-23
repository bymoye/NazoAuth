DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM backchannel_logout_deliveries AS delivery
        LEFT JOIN oauth_clients AS client
          ON client.tenant_id = delivery.tenant_id
         AND client.id = delivery.client_id
         AND client.client_id = delivery.client_public_id
        WHERE client.id IS NULL
    ) THEN
        RAISE EXCEPTION
            'cannot bind backchannel logout deliveries to tenants: mismatched client identity exists';
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_oauth_clients_tenant_internal_public_id
    ON oauth_clients (tenant_id, id, client_id);

ALTER TABLE backchannel_logout_deliveries
    DROP CONSTRAINT IF EXISTS backchannel_logout_deliveries_client_id_fkey,
    ADD CONSTRAINT fk_backchannel_logout_delivery_client_tenant
        FOREIGN KEY (tenant_id, client_id, client_public_id)
        REFERENCES oauth_clients (tenant_id, id, client_id)
        ON DELETE CASCADE;
