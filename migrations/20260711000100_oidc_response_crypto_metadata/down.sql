COMMENT ON COLUMN oauth_clients.authorization_encrypted_response_enc IS NULL;
COMMENT ON COLUMN oauth_clients.authorization_encrypted_response_alg IS NULL;
COMMENT ON COLUMN oauth_clients.authorization_signed_response_alg IS NULL;
COMMENT ON COLUMN oauth_clients.userinfo_encrypted_response_enc IS NULL;
COMMENT ON COLUMN oauth_clients.userinfo_encrypted_response_alg IS NULL;
COMMENT ON COLUMN oauth_clients.userinfo_signed_response_alg IS NULL;

ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS authorization_encrypted_response_enc,
    DROP COLUMN IF EXISTS authorization_encrypted_response_alg,
    DROP COLUMN IF EXISTS authorization_signed_response_alg,
    DROP COLUMN IF EXISTS userinfo_encrypted_response_enc,
    DROP COLUMN IF EXISTS userinfo_encrypted_response_alg,
    DROP COLUMN IF EXISTS userinfo_signed_response_alg;
