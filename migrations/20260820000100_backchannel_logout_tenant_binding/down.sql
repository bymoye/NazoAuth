ALTER TABLE backchannel_logout_deliveries
    DROP CONSTRAINT IF EXISTS fk_backchannel_logout_delivery_client_tenant,
    ADD CONSTRAINT backchannel_logout_deliveries_client_id_fkey
        FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE;

DROP INDEX IF EXISTS uq_oauth_clients_tenant_internal_public_id;
