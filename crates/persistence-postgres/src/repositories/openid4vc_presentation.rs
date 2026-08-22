use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_openid4vp::{
    PresentationResult, PresentationStoreError, PresentationStoreFuture, PresentationStorePort,
    PresentationTransaction, StoredPresentation,
};
use rand::Rng;
use uuid::Uuid;

use crate::DbPool;
#[derive(Clone)]
pub struct Openid4vpRepository {
    pool: DbPool,
    tenant_id: Uuid,
    data_key: [u8; 32],
}

pub struct NewOpenid4vpVerificationEvidence<'a> {
    pub context: &'a nazo_operator_protocol::Openid4vpEvidenceContext,
    pub context_sha256: &'a str,
    pub intent_jws: &'a str,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ExistingOpenid4vpEvidenceContext {
    Pending {
        transaction: PresentationTransaction,
        intent_jws: String,
    },
    Conflict,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CreateOpenid4vpWithEvidenceOutcome {
    Created,
    ExistingPending {
        transaction: PresentationTransaction,
        intent_jws: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredOpenid4vpVerificationEvidence {
    pub receipt_id: Uuid,
    pub transaction_id: Uuid,
    pub context: nazo_operator_protocol::Openid4vpEvidenceContext,
    pub capability_sha256: String,
    pub intent_jws: String,
    pub receipt_jws: String,
    pub completed_at: DateTime<Utc>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedOpenid4vpVerificationEvidence {
    pub transaction_id: Uuid,
    pub context: nazo_operator_protocol::Openid4vpEvidenceContext,
    pub context_sha256: String,
    pub intent_jws: String,
    pub completed_at: DateTime<Utc>,
    pub transaction_expires_at: DateTime<Utc>,
}

impl Openid4vpRepository {
    #[must_use]
    pub fn new(pool: DbPool, tenant_id: Uuid, data_key: [u8; 32]) -> Self {
        Self {
            pool,
            tenant_id,
            data_key,
        }
    }

    pub async fn create_with_verification_evidence(
        &self,
        transaction: &PresentationTransaction,
        evidence: NewOpenid4vpVerificationEvidence<'_>,
    ) -> Result<CreateOpenid4vpWithEvidenceOutcome, PresentationStoreError> {
        let context = evidence.context.clone();
        let context_sha256 = evidence.context_sha256.to_owned();
        match self.create_inner(transaction, Some(evidence)).await {
            Ok(true) => Ok(CreateOpenid4vpWithEvidenceOutcome::Created),
            Ok(false) => match self
                .presentation_by_evidence_context(&context, &context_sha256, Utc::now())
                .await?
            {
                Some(ExistingOpenid4vpEvidenceContext::Pending {
                    transaction,
                    intent_jws,
                }) => Ok(CreateOpenid4vpWithEvidenceOutcome::ExistingPending {
                    transaction,
                    intent_jws,
                }),
                _ => Err(PresentationStoreError::InvalidTransition),
            },
            Err(error) => Err(error),
        }
    }

    pub async fn presentation_by_evidence_context(
        &self,
        context: &nazo_operator_protocol::Openid4vpEvidenceContext,
        context_sha256: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ExistingOpenid4vpEvidenceContext>, PresentationStoreError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let row = load_evidence_context(&mut connection, self.tenant_id, context_sha256)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if row.context()? != *context || row.verification_context_sha256 != context_sha256 {
            return Err(PresentationStoreError::InvalidTransition);
        }
        if row.completed_at.is_some() || row.expires_at <= now {
            return Ok(Some(ExistingOpenid4vpEvidenceContext::Conflict));
        }
        let Some(transaction) = load_presentation(&mut connection, self.tenant_id, row.id, now)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?
        else {
            return Ok(Some(ExistingOpenid4vpEvidenceContext::Conflict));
        };
        if transaction.completed_at.is_some() {
            return Ok(Some(ExistingOpenid4vpEvidenceContext::Conflict));
        }
        transaction.transaction().map(|transaction| {
            Some(ExistingOpenid4vpEvidenceContext::Pending {
                transaction,
                intent_jws: row.verification_intent_jws,
            })
        })
    }

    pub async fn rotate_verification_evidence(
        &self,
        transaction_id: Uuid,
        receipt_id: Uuid,
        capability_sha256: &str,
        receipt_jws: &str,
        expected_intent_jws: &str,
        expected_context_sha256: &str,
        issued_at: DateTime<Utc>,
        requested_expires_at: DateTime<Utc>,
    ) -> Result<Option<StoredOpenid4vpVerificationEvidence>, PresentationStoreError> {
        if capability_sha256.len() != 64
            || !capability_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || requested_expires_at <= issued_at
            || requested_expires_at.signed_duration_since(issued_at)
                > chrono::Duration::seconds(600)
            || receipt_jws.is_empty()
            || receipt_jws.len() > nazo_operator_protocol::MAX_COMPACT_JWS_BYTES
            || expected_intent_jws.is_empty()
            || expected_intent_jws.len() > nazo_operator_protocol::MAX_COMPACT_JWS_BYTES
            || expected_context_sha256.len() != 64
            || !expected_context_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PresentationStoreError::InvalidTransition);
        }
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let data_key = self.data_key;
        let row = connection
            .transaction::<Option<VerificationEvidenceRow>, diesel::result::Error, _>(
                async move |connection| {
                    let locked = sql_query(
                        "SELECT id, verification_run_jti, verification_artifact_sha256, \
                             verification_matrix_sha256, verification_suite_plan_id, \
                             verification_suite_module_id, verification_test_name, \
                             verification_variant_sha256, verification_context_sha256, \
                             verification_intent_jws, result_ciphertext, completed_at, expires_at \
                         FROM openid4vp_transactions \
                         WHERE id = $1 AND tenant_id = $2 AND completed_at IS NOT NULL \
                           AND result_ciphertext IS NOT NULL AND expires_at > $3 \
                           AND verification_context_sha256 IS NOT NULL \
                           AND verification_intent_jws = $4 \
                           AND openid4vc_presentation_trust_policy_is_active( \
                               tenant_id, openid4vc_trust_policy_binding_id, \
                               openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest) \
                         FOR UPDATE",
                    )
                    .bind::<sql_types::Uuid, _>(transaction_id)
                    .bind::<sql_types::Uuid, _>(self.tenant_id)
                    .bind::<sql_types::Timestamptz, _>(issued_at)
                    .bind::<sql_types::Text, _>(expected_intent_jws)
                    .get_result::<VerificationIntentRow>(connection)
                    .await
                    .optional()?;
                    let Some(locked) = locked else {
                        return Ok(None);
                    };
                    let prepared = locked
                        .prepared(&data_key)
                        .map_err(|_| diesel::result::Error::RollbackTransaction)?;
                    if prepared.context_sha256 != expected_context_sha256 {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    sql_query(
                        "UPDATE openid4vp_transactions SET \
                 verification_receipt_id = $4, verification_capability_sha256 = $5, \
                 verification_receipt_jws = $6, verification_issued_at = $3, \
                 verification_expires_at = $7 \
             WHERE id = $1 AND tenant_id = $2 AND completed_at IS NOT NULL \
               AND result_ciphertext IS NOT NULL AND expires_at >= $7 \
               AND verification_context_sha256 IS NOT NULL \
               AND verification_intent_jws = $8 \
               AND openid4vc_presentation_trust_policy_is_active( \
                   tenant_id, openid4vc_trust_policy_binding_id, \
                   openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest) \
             RETURNING id, verification_receipt_id, verification_run_jti, \
               verification_artifact_sha256, verification_matrix_sha256, \
               verification_suite_plan_id, verification_suite_module_id, \
               verification_test_name, verification_variant_sha256, \
               verification_context_sha256, verification_intent_jws, \
               verification_capability_sha256, verification_receipt_jws, \
               result_ciphertext, completed_at, verification_issued_at, \
               verification_expires_at AS expires_at",
                    )
                    .bind::<sql_types::Uuid, _>(transaction_id)
                    .bind::<sql_types::Uuid, _>(self.tenant_id)
                    .bind::<sql_types::Timestamptz, _>(issued_at)
                    .bind::<sql_types::Uuid, _>(receipt_id)
                    .bind::<sql_types::Text, _>(capability_sha256)
                    .bind::<sql_types::Text, _>(receipt_jws)
                    .bind::<sql_types::Timestamptz, _>(requested_expires_at)
                    .bind::<sql_types::Text, _>(expected_intent_jws)
                    .get_result::<VerificationEvidenceRow>(connection)
                    .await
                    .optional()
                },
            )
            .await
            .map_err(|error| match error {
                diesel::result::Error::RollbackTransaction => {
                    PresentationStoreError::InvalidTransition
                }
                _ => PresentationStoreError::Unavailable,
            })?;
        row.map(|value| value.stored(&self.data_key)).transpose()
    }

    pub async fn prepare_verification_evidence(
        &self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<PreparedOpenid4vpVerificationEvidence>, PresentationStoreError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let row = sql_query(
            "SELECT id, verification_run_jti, verification_artifact_sha256, \
                 verification_matrix_sha256, verification_suite_plan_id, \
                 verification_suite_module_id, verification_test_name, \
                 verification_variant_sha256, verification_context_sha256, \
                 verification_intent_jws, result_ciphertext, completed_at, expires_at \
             FROM openid4vp_transactions \
             WHERE id = $1 AND tenant_id = $2 AND completed_at IS NOT NULL \
               AND result_ciphertext IS NOT NULL AND expires_at > $3 \
               AND verification_context_sha256 IS NOT NULL \
               AND openid4vc_presentation_trust_policy_is_active( \
                   tenant_id, openid4vc_trust_policy_binding_id, \
                   openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)",
        )
        .bind::<sql_types::Uuid, _>(transaction_id)
        .bind::<sql_types::Uuid, _>(self.tenant_id)
        .bind::<sql_types::Timestamptz, _>(now)
        .get_result::<VerificationIntentRow>(&mut connection)
        .await
        .optional()
        .map_err(|_| PresentationStoreError::Unavailable)?;
        row.map(|value| value.prepared(&self.data_key)).transpose()
    }

    pub async fn verification_evidence_by_capability_sha256(
        &self,
        capability_sha256: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<StoredOpenid4vpVerificationEvidence>, PresentationStoreError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        load_verification_evidence(
            &mut connection,
            self.tenant_id,
            VerificationEvidenceLookup::CapabilitySha256(capability_sha256),
            now,
        )
        .await
        .map_err(|_| PresentationStoreError::Unavailable)?
        .map(|row| row.stored(&self.data_key))
        .transpose()
    }

    async fn create_inner(
        &self,
        transaction: &PresentationTransaction,
        evidence: Option<NewOpenid4vpVerificationEvidence<'_>>,
    ) -> Result<bool, PresentationStoreError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let state_hash = blake3::hash(transaction.request.state.as_bytes())
            .to_hex()
            .to_string();
        let protected_private_key = transaction
            .response_encryption_private_key
            .as_deref()
            .map(|key| protect_result(&self.data_key, transaction.id, key))
            .transpose()?;
        let context = evidence.as_ref().map(|value| value.context);
        let verification_suite_plan_id = context
            .map(|value| Uuid::parse_str(&value.suite_plan_id))
            .transpose()
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        let verification_suite_module_id = context
            .map(|value| Uuid::parse_str(&value.suite_module_id))
            .transpose()
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        if let Some(value) = evidence.as_ref() {
            let canonical =
                nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(value.context)
                    .map_err(|_| PresentationStoreError::InvalidTransition)?;
            if canonical != value.context_sha256
                || value.intent_jws.is_empty()
                || value.intent_jws.len() > nazo_operator_protocol::MAX_COMPACT_JWS_BYTES
            {
                return Err(PresentationStoreError::InvalidTransition);
            }
        }
        let insert = if evidence.is_some() {
            "INSERT INTO openid4vp_transactions \
             (id, tenant_id, client_id_prefix, request_method, response_mode, \
              wallet_authorization_endpoint, state_hash, request, request_object, request_uri, \
              openid4vc_trust_policy_binding_id, openid4vc_trust_policy_resource_id, \
              openid4vc_trust_policy_digest, ephemeral_private_key_ciphertext, expires_at, \
              verification_run_jti, verification_artifact_sha256, \
              verification_matrix_sha256, verification_suite_plan_id, \
              verification_suite_module_id, verification_test_name, verification_variant_sha256, \
              verification_context_sha256, verification_intent_jws) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24) \
             ON CONFLICT (tenant_id, verification_context_sha256) \
             WHERE verification_context_sha256 IS NOT NULL DO NOTHING"
        } else {
            "INSERT INTO openid4vp_transactions \
             (id, tenant_id, client_id_prefix, request_method, response_mode, \
              wallet_authorization_endpoint, state_hash, request, request_object, request_uri, \
              openid4vc_trust_policy_binding_id, openid4vc_trust_policy_resource_id, \
              openid4vc_trust_policy_digest, ephemeral_private_key_ciphertext, expires_at, \
              verification_run_jti, verification_artifact_sha256, \
              verification_matrix_sha256, verification_suite_plan_id, \
              verification_suite_module_id, verification_test_name, verification_variant_sha256, \
              verification_context_sha256, verification_intent_jws) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)"
        };
        let inserted = sql_query(insert)
            .bind::<sql_types::Uuid, _>(transaction.id)
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::Text, _>(transaction.client_id_prefix.as_str())
            .bind::<sql_types::Text, _>(transaction.request_method.as_str())
            .bind::<sql_types::Text, _>(transaction.response_mode.as_str())
            .bind::<sql_types::Text, _>(&transaction.wallet_authorization_endpoint)
            .bind::<sql_types::Text, _>(state_hash)
            .bind::<sql_types::Jsonb, _>(
                serde_json::to_value(&transaction.request)
                    .map_err(|_| PresentationStoreError::InvalidTransition)?,
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(transaction.request_object.as_deref())
            .bind::<sql_types::Nullable<sql_types::Text>, _>(transaction.request_uri.as_deref())
            .bind::<sql_types::Nullable<sql_types::Uuid>, _>(
                transaction.openid4vc_trust_policy_binding_id,
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                transaction.openid4vc_trust_policy_resource_id.as_deref(),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                transaction.openid4vc_trust_policy_digest.as_deref(),
            )
            .bind::<sql_types::Nullable<sql_types::Binary>, _>(protected_private_key)
            .bind::<sql_types::Timestamptz, _>(transaction.expires_at)
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                context.map(|value| value.run_jti.as_str()),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                context.map(|value| value.artifact_sha256.as_str()),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                context.map(|value| value.matrix_sha256.as_str()),
            )
            .bind::<sql_types::Nullable<sql_types::Uuid>, _>(verification_suite_plan_id)
            .bind::<sql_types::Nullable<sql_types::Uuid>, _>(verification_suite_module_id)
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                context.map(|value| value.test_name.as_str()),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                context.map(|value| value.variant_sha256.as_str()),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                evidence.as_ref().map(|value| value.context_sha256),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                evidence.as_ref().map(|value| value.intent_jws),
            )
            .execute(&mut connection)
            .await
            .map_err(|error| match error {
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                ) => PresentationStoreError::InvalidTransition,
                _ => PresentationStoreError::Unavailable,
            })?;
        Ok(inserted == 1)
    }
}

impl PresentationStorePort for Openid4vpRepository {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
    ) -> PresentationStoreFuture<'a, Result<(), PresentationStoreError>> {
        Box::pin(async move {
            match self.create_inner(transaction, None).await? {
                true => Ok(()),
                false => Err(PresentationStoreError::InvalidTransition),
            }
        })
    }

    fn request<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let row = load_presentation(&mut connection, self.tenant_id, transaction_id, now)
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            row.map(|value| value.transaction_with_key(&self.data_key))
                .transpose()
        })
    }

    fn bind_wallet_nonce<'a>(
        &'a self,
        transaction_id: Uuid,
        wallet_nonce: &'a str,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let Some(mut row) =
                load_presentation(&mut connection, self.tenant_id, transaction_id, now)
                    .await
                    .map_err(|_| PresentationStoreError::Unavailable)?
            else {
                return Ok(None);
            };
            let mut request = row.transaction()?.request;
            request.wallet_nonce = Some(wallet_nonce.to_owned());
            let encoded = serde_json::to_value(&request)
                .map_err(|_| PresentationStoreError::InvalidTransition)?;
            let changed = sql_query(
                "UPDATE openid4vp_transactions SET request = $4 \
                 WHERE id = $1 AND tenant_id = $2 AND completed_at IS NULL AND expires_at > $3 \
                   AND openid4vc_presentation_trust_policy_is_active( \
                       tenant_id, openid4vc_trust_policy_binding_id, \
                       openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)",
            )
            .bind::<sql_types::Uuid, _>(transaction_id)
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::Timestamptz, _>(now)
            .bind::<sql_types::Jsonb, _>(&encoded)
            .execute(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
            if changed != 1 {
                return Ok(None);
            }
            row.request = encoded;
            row.transaction_with_key(&self.data_key).map(Some)
        })
    }

    fn complete<'a>(
        &'a self,
        transaction_id: Uuid,
        state_hash: &'a str,
        result: &'a PresentationResult,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<bool, PresentationStoreError>> {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let encoded = serde_json::to_vec(result)
                .map_err(|_| PresentationStoreError::InvalidTransition)?;
            let encoded = protect_result(&self.data_key, transaction_id, &encoded)?;
            let changed = sql_query(
                "UPDATE openid4vp_transactions SET result_ciphertext = $5, completed_at = $4, \
                     ephemeral_private_key_ciphertext = NULL \
                 WHERE id = $1 AND tenant_id = $2 AND state_hash = $3 \
                   AND completed_at IS NULL AND expires_at > $4 \
                   AND openid4vc_presentation_trust_policy_is_active( \
                       tenant_id, openid4vc_trust_policy_binding_id, \
                       openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)",
            )
            .bind::<sql_types::Uuid, _>(transaction_id)
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::Text, _>(state_hash)
            .bind::<sql_types::Timestamptz, _>(now)
            .bind::<sql_types::Binary, _>(encoded)
            .execute(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
            Ok(changed == 1)
        })
    }

    fn result<'a>(
        &'a self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<StoredPresentation>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            let row = load_presentation(&mut connection, self.tenant_id, transaction_id, now)
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            row.map(|value| value.stored(&self.data_key)).transpose()
        })
    }
}

#[derive(QueryableByName)]
struct PresentationRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    client_id_prefix: String,
    #[diesel(sql_type = sql_types::Text)]
    request_method: String,
    #[diesel(sql_type = sql_types::Text)]
    response_mode: String,
    #[diesel(sql_type = sql_types::Text)]
    wallet_authorization_endpoint: String,
    #[diesel(sql_type = sql_types::Jsonb)]
    request: serde_json::Value,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    request_object: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    request_uri: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    openid4vc_trust_policy_binding_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_resource_id: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_digest: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Binary>)]
    ephemeral_private_key_ciphertext: Option<Vec<u8>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Binary>)]
    result_ciphertext: Option<Vec<u8>>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    completed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct VerificationEvidenceRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    verification_receipt_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    verification_run_jti: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_artifact_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_matrix_sha256: String,
    #[diesel(sql_type = sql_types::Uuid)]
    verification_suite_plan_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    verification_suite_module_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    verification_test_name: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_variant_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_context_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_intent_jws: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_capability_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_receipt_jws: String,
    #[diesel(sql_type = sql_types::Binary)]
    result_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    completed_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    verification_issued_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

#[derive(QueryableByName)]
struct VerificationIntentRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    verification_run_jti: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_artifact_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_matrix_sha256: String,
    #[diesel(sql_type = sql_types::Uuid)]
    verification_suite_plan_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    verification_suite_module_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    verification_test_name: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_variant_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_context_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_intent_jws: String,
    #[diesel(sql_type = sql_types::Binary)]
    result_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    completed_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

impl VerificationIntentRow {
    fn prepared(
        self,
        data_key: &[u8; 32],
    ) -> Result<PreparedOpenid4vpVerificationEvidence, PresentationStoreError> {
        let result = unprotect_result(data_key, self.id, &self.result_ciphertext)?;
        let result: PresentationResult = serde_json::from_slice(&result)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        if result.transaction_id != self.id
            || result.completed_at.timestamp_micros() != self.completed_at.timestamp_micros()
        {
            return Err(PresentationStoreError::InvalidTransition);
        }
        let context = nazo_operator_protocol::Openid4vpEvidenceContext {
            run_jti: self.verification_run_jti,
            artifact_sha256: self.verification_artifact_sha256,
            matrix_sha256: self.verification_matrix_sha256,
            suite_plan_id: self.verification_suite_plan_id.to_string(),
            suite_module_id: self.verification_suite_module_id.to_string(),
            test_name: self.verification_test_name,
            variant_sha256: self.verification_variant_sha256,
        };
        let digest = nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(&context)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        if digest != self.verification_context_sha256 {
            return Err(PresentationStoreError::InvalidTransition);
        }
        Ok(PreparedOpenid4vpVerificationEvidence {
            transaction_id: self.id,
            context,
            context_sha256: digest,
            intent_jws: self.verification_intent_jws,
            completed_at: self.completed_at,
            transaction_expires_at: self.expires_at,
        })
    }
}

#[derive(QueryableByName)]
struct EvidenceContextRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    verification_run_jti: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_artifact_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_matrix_sha256: String,
    #[diesel(sql_type = sql_types::Uuid)]
    verification_suite_plan_id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    verification_suite_module_id: Uuid,
    #[diesel(sql_type = sql_types::Text)]
    verification_test_name: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_variant_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_context_sha256: String,
    #[diesel(sql_type = sql_types::Text)]
    verification_intent_jws: String,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    completed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

impl EvidenceContextRow {
    fn context(
        &self,
    ) -> Result<nazo_operator_protocol::Openid4vpEvidenceContext, PresentationStoreError> {
        let context = nazo_operator_protocol::Openid4vpEvidenceContext {
            run_jti: self.verification_run_jti.clone(),
            artifact_sha256: self.verification_artifact_sha256.clone(),
            matrix_sha256: self.verification_matrix_sha256.clone(),
            suite_plan_id: self.verification_suite_plan_id.to_string(),
            suite_module_id: self.verification_suite_module_id.to_string(),
            test_name: self.verification_test_name.clone(),
            variant_sha256: self.verification_variant_sha256.clone(),
        };
        let digest = nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(&context)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        if digest != self.verification_context_sha256 {
            return Err(PresentationStoreError::InvalidTransition);
        }
        Ok(context)
    }
}

impl VerificationEvidenceRow {
    fn stored(
        self,
        data_key: &[u8; 32],
    ) -> Result<StoredOpenid4vpVerificationEvidence, PresentationStoreError> {
        let result = unprotect_result(data_key, self.id, &self.result_ciphertext)?;
        let result: PresentationResult = serde_json::from_slice(&result)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        if result.transaction_id != self.id
            || result.completed_at.timestamp_micros() != self.completed_at.timestamp_micros()
        {
            return Err(PresentationStoreError::InvalidTransition);
        }
        let context = nazo_operator_protocol::Openid4vpEvidenceContext {
            run_jti: self.verification_run_jti,
            artifact_sha256: self.verification_artifact_sha256,
            matrix_sha256: self.verification_matrix_sha256,
            suite_plan_id: self.verification_suite_plan_id.to_string(),
            suite_module_id: self.verification_suite_module_id.to_string(),
            test_name: self.verification_test_name,
            variant_sha256: self.verification_variant_sha256,
        };
        let context_sha256 =
            nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(&context)
                .map_err(|_| PresentationStoreError::InvalidTransition)?;
        if context_sha256 != self.verification_context_sha256 {
            return Err(PresentationStoreError::InvalidTransition);
        }
        Ok(StoredOpenid4vpVerificationEvidence {
            receipt_id: self.verification_receipt_id,
            transaction_id: self.id,
            context,
            capability_sha256: self.verification_capability_sha256,
            intent_jws: self.verification_intent_jws,
            receipt_jws: self.verification_receipt_jws,
            completed_at: self.completed_at,
            issued_at: self.verification_issued_at,
            expires_at: self.expires_at,
        })
    }
}

enum VerificationEvidenceLookup<'a> {
    CapabilitySha256(&'a str),
}

async fn load_evidence_context(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    context_sha256: &str,
) -> Result<Option<EvidenceContextRow>, diesel::result::Error> {
    sql_query(
        "SELECT id, verification_run_jti, verification_artifact_sha256, \
             verification_matrix_sha256, verification_suite_plan_id, \
             verification_suite_module_id, verification_test_name, \
             verification_variant_sha256, verification_context_sha256, \
             verification_intent_jws, \
             completed_at, expires_at \
         FROM openid4vp_transactions \
         WHERE tenant_id = $1 AND verification_context_sha256 = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(context_sha256)
    .get_result(connection)
    .await
    .optional()
}

async fn load_verification_evidence(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    lookup: VerificationEvidenceLookup<'_>,
    now: DateTime<Utc>,
) -> Result<Option<VerificationEvidenceRow>, diesel::result::Error> {
    let projection = "SELECT id, verification_receipt_id, verification_run_jti, \
         verification_artifact_sha256, verification_matrix_sha256, \
         verification_suite_plan_id, verification_suite_module_id, \
         verification_test_name, verification_variant_sha256, \
         verification_context_sha256, verification_intent_jws, \
         verification_capability_sha256, verification_receipt_jws, \
         result_ciphertext, completed_at, verification_issued_at, \
         verification_expires_at AS expires_at \
         FROM openid4vp_transactions";
    let suffix = " AND completed_at IS NOT NULL AND result_ciphertext IS NOT NULL \
         AND verification_receipt_id IS NOT NULL \
         AND expires_at > $3 AND verification_expires_at > $3 \
         AND openid4vc_presentation_trust_policy_is_active( \
             tenant_id, openid4vc_trust_policy_binding_id, \
             openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)";
    match lookup {
        VerificationEvidenceLookup::CapabilitySha256(capability_sha256) => sql_query(format!(
            "{projection} WHERE tenant_id = $1 AND verification_capability_sha256 = $2{suffix}"
        ))
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Text, _>(capability_sha256)
        .bind::<sql_types::Timestamptz, _>(now)
        .get_result(connection)
        .await
        .optional(),
    }
}

impl PresentationRow {
    fn transaction(&self) -> Result<PresentationTransaction, PresentationStoreError> {
        Ok(PresentationTransaction {
            id: self.id,
            client_id_prefix: parse_client_id_prefix(&self.client_id_prefix)?,
            request_method: self
                .request_method
                .parse()
                .map_err(|_| PresentationStoreError::InvalidTransition)?,
            response_mode: parse_response_mode(&self.response_mode)?,
            wallet_authorization_endpoint: self.wallet_authorization_endpoint.clone(),
            request: serde_json::from_value(self.request.clone())
                .map_err(|_| PresentationStoreError::InvalidTransition)?,
            request_object: self.request_object.clone(),
            request_uri: self.request_uri.clone(),
            openid4vc_trust_policy_binding_id: self.openid4vc_trust_policy_binding_id,
            openid4vc_trust_policy_resource_id: self.openid4vc_trust_policy_resource_id.clone(),
            openid4vc_trust_policy_digest: self.openid4vc_trust_policy_digest.clone(),
            response_encryption_private_key: None,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
    fn transaction_with_key(
        &self,
        data_key: &[u8; 32],
    ) -> Result<PresentationTransaction, PresentationStoreError> {
        let mut transaction = self.transaction()?;
        transaction.response_encryption_private_key = self
            .ephemeral_private_key_ciphertext
            .as_deref()
            .map(|value| unprotect_result(data_key, self.id, value))
            .transpose()?;
        Ok(transaction)
    }
    fn stored(self, data_key: &[u8; 32]) -> Result<StoredPresentation, PresentationStoreError> {
        let decrypted = self
            .result_ciphertext
            .as_deref()
            .map(|value| unprotect_result(data_key, self.id, value))
            .transpose()?;
        let completed = decrypted
            .as_deref()
            .map(serde_json::from_slice)
            .transpose()
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        let mut transaction = self.transaction()?;
        transaction.response_encryption_private_key = self
            .ephemeral_private_key_ciphertext
            .as_deref()
            .map(|value| unprotect_result(data_key, self.id, value))
            .transpose()?;
        if completed
            .as_ref()
            .map(|result: &PresentationResult| result.completed_at.timestamp_micros())
            != self
                .completed_at
                .map(|completed_at| completed_at.timestamp_micros())
        {
            return Err(PresentationStoreError::InvalidTransition);
        }
        Ok(StoredPresentation {
            transaction,
            completed,
        })
    }
}

async fn load_presentation(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<PresentationRow>, diesel::result::Error> {
    sql_query(
        "SELECT id, client_id_prefix, request_method, response_mode, wallet_authorization_endpoint, \
         request, request_object, request_uri, openid4vc_trust_policy_binding_id, \
         openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest, \
         ephemeral_private_key_ciphertext, result_ciphertext, completed_at, expires_at, created_at \
         FROM openid4vp_transactions WHERE id = $1 AND tenant_id = $2 AND expires_at > $3 \
           AND openid4vc_presentation_trust_policy_is_active( \
               tenant_id, openid4vc_trust_policy_binding_id, \
               openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)",
    )
    .bind::<sql_types::Uuid, _>(id)
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Timestamptz, _>(now)
    .get_result(connection)
    .await
    .optional()
}

fn parse_client_id_prefix(
    value: &str,
) -> Result<nazo_openid4vp::ClientIdPrefix, PresentationStoreError> {
    match value {
        "redirect_uri" => Ok(nazo_openid4vp::ClientIdPrefix::RedirectUri),
        "x509_san_dns" => Ok(nazo_openid4vp::ClientIdPrefix::X509SanDns),
        "x509_hash" => Ok(nazo_openid4vp::ClientIdPrefix::X509Hash),
        _ => Err(PresentationStoreError::InvalidTransition),
    }
}

fn parse_response_mode(
    value: &str,
) -> Result<nazo_openid4vp::ResponseMode, PresentationStoreError> {
    match value {
        "direct_post" => Ok(nazo_openid4vp::ResponseMode::DirectPost),
        "direct_post.jwt" => Ok(nazo_openid4vp::ResponseMode::DirectPostJwt),
        _ => Err(PresentationStoreError::InvalidTransition),
    }
}

fn protect_result(
    key: &[u8; 32],
    transaction_id: Uuid,
    plaintext: &[u8],
) -> Result<Vec<u8>, PresentationStoreError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PresentationStoreError::Unavailable)?;
    let mut nonce = [0_u8; 12];
    rand::rng().fill_bytes(&mut nonce);
    let mut protected = nonce.to_vec();
    protected.extend_from_slice(
        &cipher
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: transaction_id.as_bytes(),
                },
            )
            .map_err(|_| PresentationStoreError::Unavailable)?,
    );
    Ok(protected)
}

fn unprotect_result(
    key: &[u8; 32],
    transaction_id: Uuid,
    protected: &[u8],
) -> Result<Vec<u8>, PresentationStoreError> {
    let (nonce, ciphertext) = protected
        .split_at_checked(12)
        .ok_or(PresentationStoreError::InvalidTransition)?;
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| PresentationStoreError::Unavailable)?
        .decrypt(
            nonce.into(),
            Payload {
                msg: ciphertext,
                aad: transaction_id.as_bytes(),
            },
        )
        .map_err(|_| PresentationStoreError::InvalidTransition)
}
