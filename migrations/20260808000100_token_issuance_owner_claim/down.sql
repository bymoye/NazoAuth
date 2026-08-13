ALTER TABLE oauth_token_issuances
    DROP CONSTRAINT oauth_token_issuances_claim_owner_pair_check;

ALTER TABLE oauth_token_issuances
    DROP COLUMN claim_owner_id,
    DROP COLUMN claim_started_at;

