ALTER TABLE oauth_token_issuances
    ADD COLUMN claim_owner_id UUID,
    ADD COLUMN claim_started_at TIMESTAMPTZ;

ALTER TABLE oauth_token_issuances
    ADD CONSTRAINT oauth_token_issuances_claim_owner_pair_check
    CHECK ((claim_owner_id IS NULL) = (claim_started_at IS NULL));

