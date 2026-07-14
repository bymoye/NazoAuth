DROP INDEX IF EXISTS uq_backchannel_logout_operation_client;

ALTER TABLE backchannel_logout_deliveries
    DROP COLUMN IF EXISTS operation_key;
