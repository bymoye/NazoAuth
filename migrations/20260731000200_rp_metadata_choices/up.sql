ALTER TABLE oauth_clients
    ADD COLUMN id_token_signed_response_alg VARCHAR NULL,
    ADD COLUMN id_token_encrypted_response_alg VARCHAR NULL,
    ADD COLUMN id_token_encrypted_response_enc VARCHAR NULL,
    ADD COLUMN request_object_signing_alg VARCHAR NULL,
    ADD COLUMN request_object_encryption_alg VARCHAR NULL,
    ADD COLUMN request_object_encryption_enc VARCHAR NULL,
    ADD COLUMN token_endpoint_auth_signing_alg VARCHAR NULL,
    ADD COLUMN introspection_signed_response_alg VARCHAR NULL;
