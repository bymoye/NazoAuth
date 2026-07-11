ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS userinfo_signed_response_alg VARCHAR,
    ADD COLUMN IF NOT EXISTS userinfo_encrypted_response_alg VARCHAR,
    ADD COLUMN IF NOT EXISTS userinfo_encrypted_response_enc VARCHAR,
    ADD COLUMN IF NOT EXISTS authorization_signed_response_alg VARCHAR,
    ADD COLUMN IF NOT EXISTS authorization_encrypted_response_alg VARCHAR,
    ADD COLUMN IF NOT EXISTS authorization_encrypted_response_enc VARCHAR;

COMMENT ON COLUMN oauth_clients.userinfo_signed_response_alg IS
    'OIDC JWS alg required for signed UserInfo responses.';
COMMENT ON COLUMN oauth_clients.userinfo_encrypted_response_alg IS
    'OIDC JWE alg required for encrypted UserInfo responses.';
COMMENT ON COLUMN oauth_clients.userinfo_encrypted_response_enc IS
    'OIDC JWE enc required for encrypted UserInfo responses.';
COMMENT ON COLUMN oauth_clients.authorization_signed_response_alg IS
    'JARM JWS alg required for signed authorization responses.';
COMMENT ON COLUMN oauth_clients.authorization_encrypted_response_alg IS
    'JARM JWE alg required for encrypted authorization responses.';
COMMENT ON COLUMN oauth_clients.authorization_encrypted_response_enc IS
    'JARM JWE enc required for encrypted authorization responses.';
