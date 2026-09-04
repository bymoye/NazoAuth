COMMENT ON COLUMN oauth_clients.allow_client_assertion_audience_array IS NULL;
COMMENT ON COLUMN oauth_clients.allow_client_assertion_endpoint_audience IS NULL;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS allow_client_assertion_endpoint_audience,
    DROP COLUMN IF EXISTS allow_client_assertion_audience_array;
