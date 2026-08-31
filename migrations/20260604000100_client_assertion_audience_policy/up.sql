ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS allow_client_assertion_audience_array BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS allow_client_assertion_endpoint_audience BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN oauth_clients.allow_client_assertion_audience_array IS
    'Allows private_key_jwt client assertion aud to be a JSON array containing an accepted audience.';
COMMENT ON COLUMN oauth_clients.allow_client_assertion_endpoint_audience IS
    'Allows private_key_jwt client assertion aud to match the authenticated endpoint URL.';
