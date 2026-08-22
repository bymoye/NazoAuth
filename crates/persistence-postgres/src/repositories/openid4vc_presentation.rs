use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use chrono::{DateTime, Utc};
use diesel::{OptionalExtension, QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_openid4vp::{
    PresentationCreateIdempotency, PresentationCreateOutcome, PresentationResult,
    PresentationStoreError, PresentationStoreFuture, PresentationStorePort,
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

pub struct NewOpenid4vpVerificationAttachment<'a> {
    pub context: &'a nazo_operator_protocol::Openid4vpEvidenceContext,
    pub context_sha256: &'a str,
    pub intent_jws: &'a str,
    pub presentation_request_sha256: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredOpenid4vpVerificationAttachment {
    pub transaction_id: Uuid,
    pub context: nazo_operator_protocol::Openid4vpEvidenceContext,
    pub context_sha256: String,
    pub intent_jws: String,
    pub presentation_binding: nazo_operator_protocol::Openid4vpPresentationBinding,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Openid4vpVerificationAttachmentState {
    Pending {
        transaction_id: Uuid,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    },
    Attached(StoredOpenid4vpVerificationAttachment),
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredOpenid4vpVerificationEvidence {
    pub receipt_id: Uuid,
    pub transaction_id: Uuid,
    pub context: nazo_operator_protocol::Openid4vpEvidenceContext,
    pub capability_sha256: String,
    pub issuance_request_jti: String,
    pub intent_jws: String,
    pub receipt_jws: String,
    pub presentation_binding: nazo_operator_protocol::Openid4vpPresentationBinding,
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
    pub presentation_binding: nazo_operator_protocol::Openid4vpPresentationBinding,
    pub completed_at: DateTime<Utc>,
    pub issuance_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedOpenid4vpVerificationEvidence {
    pub evidence: StoredOpenid4vpVerificationEvidence,
    pub capability: String,
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

    pub async fn verification_attachment_state(
        &self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<Openid4vpVerificationAttachmentState>, PresentationStoreError> {
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let row = load_verification_attachment(&mut connection, self.tenant_id, transaction_id)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if row.expires_at <= now {
            return Ok(None);
        }
        row.state().map(Some)
    }

    pub async fn attach_verification_evidence(
        &self,
        transaction_id: Uuid,
        evidence: NewOpenid4vpVerificationAttachment<'_>,
        now: DateTime<Utc>,
    ) -> Result<Option<StoredOpenid4vpVerificationAttachment>, PresentationStoreError> {
        validate_new_verification_attachment(&evidence)?;
        let context = evidence.context;
        let plan_id = Uuid::parse_str(&context.suite_plan_id)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        let module_id = Uuid::parse_str(&context.suite_module_id)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        cleanup_expired_transactions(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let updated = sql_query(
            "UPDATE openid4vp_transactions SET \
                 verification_run_jti = $4, verification_artifact_sha256 = $5, \
                 verification_matrix_sha256 = $6, verification_suite_plan_id = $7, \
                 verification_suite_module_id = $8, verification_test_name = $9, \
                 verification_variant_sha256 = $10, verification_context_sha256 = $11, \
                 verification_intent_jws = $12, verification_presentation_request_sha256 = $13 \
             WHERE id = $1 AND tenant_id = $2 AND completed_at IS NULL AND expires_at > $3 \
               AND create_request_jti IS NOT NULL \
               AND create_request_sha256 IS NOT NULL \
               AND create_request_canonical_json IS NOT NULL \
               AND verification_context_sha256 IS NULL AND verification_intent_jws IS NULL \
               AND openid4vc_presentation_trust_policy_is_active( \
                   tenant_id, openid4vc_trust_policy_binding_id, \
                   openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest) \
             RETURNING id, verification_run_jti, verification_artifact_sha256, \
               verification_matrix_sha256, verification_suite_plan_id, \
               verification_suite_module_id, verification_test_name, \
               verification_variant_sha256, verification_context_sha256, \
               verification_intent_jws, verification_presentation_request_sha256, \
               openid4vc_trust_policy_binding_id, openid4vc_trust_policy_resource_id, \
               openid4vc_trust_policy_digest, completed_at, created_at, expires_at",
        )
        .bind::<sql_types::Uuid, _>(transaction_id)
        .bind::<sql_types::Uuid, _>(self.tenant_id)
        .bind::<sql_types::Timestamptz, _>(now)
        .bind::<sql_types::Text, _>(&context.run_jti)
        .bind::<sql_types::Text, _>(&context.artifact_sha256)
        .bind::<sql_types::Text, _>(&context.matrix_sha256)
        .bind::<sql_types::Uuid, _>(plan_id)
        .bind::<sql_types::Uuid, _>(module_id)
        .bind::<sql_types::Text, _>(&context.test_name)
        .bind::<sql_types::Text, _>(&context.variant_sha256)
        .bind::<sql_types::Text, _>(evidence.context_sha256)
        .bind::<sql_types::Text, _>(evidence.intent_jws)
        .bind::<sql_types::Text, _>(evidence.presentation_request_sha256)
        .get_result::<VerificationAttachmentRow>(&mut connection)
        .await
        .optional();
        let updated = match updated {
            Ok(value) => value,
            Err(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            )) => return Err(PresentationStoreError::InvalidTransition),
            Err(_) => return Err(PresentationStoreError::Unavailable),
        };
        if let Some(updated) = updated {
            return updated.attachment().map(Some);
        }
        match self
            .verification_attachment_state(transaction_id, now)
            .await?
        {
            Some(Openid4vpVerificationAttachmentState::Attached(existing))
                if existing.context == *context
                    && existing.context_sha256 == evidence.context_sha256
                    && existing.presentation_binding.presentation_request_sha256
                        == evidence.presentation_request_sha256 =>
            {
                Ok(Some(existing))
            }
            Some(_) => Err(PresentationStoreError::InvalidTransition),
            None => Ok(None),
        }
    }

    pub async fn verification_attachment_for_completion(
        &self,
        transaction_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<StoredOpenid4vpVerificationAttachment>, PresentationStoreError> {
        match self
            .verification_attachment_state(transaction_id, now)
            .await?
        {
            Some(Openid4vpVerificationAttachmentState::Attached(attachment)) => {
                Ok(Some(attachment))
            }
            Some(Openid4vpVerificationAttachmentState::Pending { .. }) => Ok(None),
            Some(Openid4vpVerificationAttachmentState::Conflict) | None => {
                Err(PresentationStoreError::InvalidTransition)
            }
        }
    }

    pub async fn issue_verification_evidence(
        &self,
        transaction_id: Uuid,
        receipt_id: Uuid,
        issuance_request_jti: &str,
        capability: &str,
        capability_sha256: &str,
        receipt_jws: &str,
        expected_intent_jws: &str,
        expected_context_sha256: &str,
        expected_presentation_binding: &nazo_operator_protocol::Openid4vpPresentationBinding,
        issued_at: DateTime<Utc>,
        requested_expires_at: DateTime<Utc>,
    ) -> Result<Option<IssuedOpenid4vpVerificationEvidence>, PresentationStoreError> {
        let computed_capability_sha256 =
            nazo_operator_protocol::openid4vp_verification_capability_sha256(capability)
                .map_err(|_| PresentationStoreError::InvalidTransition)?;
        if !matches!(
            Uuid::parse_str(issuance_request_jti),
            Ok(value) if value.to_string() == issuance_request_jti
        ) || computed_capability_sha256 != capability_sha256
            || capability_sha256.len() != 64
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
            || nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                expected_presentation_binding,
            )
            .is_err()
        {
            return Err(PresentationStoreError::InvalidTransition);
        }
        let capability_ciphertext = protect_verification_capability(
            &self.data_key,
            self.tenant_id,
            transaction_id,
            expected_context_sha256,
            expected_intent_jws,
            expected_presentation_binding,
            issuance_request_jti,
            capability,
        )?;
        let expected_presentation_binding = expected_presentation_binding.clone();
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        cleanup_expired_transactions(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let data_key = self.data_key;
        let row = connection
            .transaction::<Option<(VerificationEvidenceRow, String)>, diesel::result::Error, _>(
                async move |connection| {
                    let locked = sql_query(
                        "SELECT id, tenant_id, verification_run_jti, verification_artifact_sha256, \
                             verification_matrix_sha256, verification_suite_plan_id, \
                             verification_suite_module_id, verification_test_name, \
                             verification_variant_sha256, verification_context_sha256, \
                             verification_intent_jws, verification_presentation_request_sha256, \
                             openid4vc_trust_policy_binding_id, \
                             openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest, \
                             result_ciphertext, completed_at, \
                             verification_issuance_expires_at AS expires_at \
                         FROM openid4vp_transactions \
                         WHERE id = $1 AND tenant_id = $2 AND completed_at IS NOT NULL \
                           AND result_ciphertext IS NOT NULL \
                           AND verification_issuance_expires_at > $3 \
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
                    if prepared.presentation_binding != expected_presentation_binding {
                        return Err(diesel::result::Error::RollbackTransaction);
                    }
                    if let Some(existing) = load_verification_evidence(
                        connection,
                        self.tenant_id,
                        VerificationEvidenceLookup::TransactionId(transaction_id),
                        issued_at,
                    )
                    .await?
                    {
                        if existing.verification_issuance_request_jti == issuance_request_jti {
                            let replayed_capability = unprotect_verification_capability(
                                &data_key,
                                self.tenant_id,
                                transaction_id,
                                &existing.verification_context_sha256,
                                &existing.verification_intent_jws,
                                &nazo_operator_protocol::Openid4vpPresentationBinding {
                                    presentation_request_sha256: existing
                                        .verification_presentation_request_sha256
                                        .clone(),
                                    trust_policy:
                                        nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                                            binding_id: existing
                                                .openid4vc_trust_policy_binding_id
                                                .map(|value| value.to_string()),
                                            resource_id: existing
                                                .openid4vc_trust_policy_resource_id
                                                .clone(),
                                            resource_digest: existing
                                                .openid4vc_trust_policy_digest
                                                .clone(),
                                        },
                                },
                                &existing.verification_issuance_request_jti,
                                &existing.verification_capability_ciphertext,
                            )
                            .map_err(|_| diesel::result::Error::RollbackTransaction)?;
                            let replayed_sha256 =
                                nazo_operator_protocol::openid4vp_verification_capability_sha256(
                                    &replayed_capability,
                                )
                                .map_err(|_| diesel::result::Error::RollbackTransaction)?;
                            if replayed_sha256 != existing.verification_capability_sha256 {
                                return Err(diesel::result::Error::RollbackTransaction);
                            }
                            return Ok(Some((existing, replayed_capability)));
                        }
                    }
                    sql_query(
                        "INSERT INTO openid4vp_verification_issuance_jtis \
                             (tenant_id, transaction_id, issuance_request_jti) \
                         VALUES ($1, $2, $3)",
                    )
                    .bind::<sql_types::Uuid, _>(self.tenant_id)
                    .bind::<sql_types::Uuid, _>(transaction_id)
                    .bind::<sql_types::Text, _>(issuance_request_jti)
                    .execute(connection)
                    .await?;
                    let updated = sql_query(
                        "UPDATE openid4vp_transactions SET \
                 verification_receipt_id = $4, verification_capability_sha256 = $5, \
                 verification_receipt_jws = $6, verification_issued_at = $3, \
                 verification_expires_at = $7, verification_issuance_request_jti = $9, \
                 verification_capability_ciphertext = $10 \
             WHERE id = $1 AND tenant_id = $2 AND completed_at IS NOT NULL \
               AND result_ciphertext IS NOT NULL AND verification_issuance_expires_at > $3 \
               AND verification_context_sha256 IS NOT NULL \
               AND verification_intent_jws = $8 \
               AND openid4vc_presentation_trust_policy_is_active( \
                   tenant_id, openid4vc_trust_policy_binding_id, \
                   openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest) \
             RETURNING id, tenant_id, verification_receipt_id, verification_run_jti, \
               verification_artifact_sha256, verification_matrix_sha256, \
               verification_suite_plan_id, verification_suite_module_id, \
               verification_test_name, verification_variant_sha256, \
               verification_context_sha256, verification_intent_jws, \
               verification_presentation_request_sha256, \
               openid4vc_trust_policy_binding_id, openid4vc_trust_policy_resource_id, \
               openid4vc_trust_policy_digest, verification_capability_sha256, \
               verification_capability_ciphertext, verification_issuance_request_jti, \
               verification_receipt_jws, \
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
                    .bind::<sql_types::Text, _>(issuance_request_jti)
                    .bind::<sql_types::Binary, _>(&capability_ciphertext)
                    .get_result::<VerificationEvidenceRow>(connection)
                    .await
                    .optional()?;
                    Ok(updated.map(|row| (row, capability.to_owned())))
                },
            )
            .await
            .map_err(|error| match error {
                diesel::result::Error::RollbackTransaction => {
                    PresentationStoreError::InvalidTransition
                }
                diesel::result::Error::DatabaseError(
                    diesel::result::DatabaseErrorKind::UniqueViolation,
                    _,
                ) => PresentationStoreError::InvalidTransition,
                _ => PresentationStoreError::Unavailable,
            })?;
        row.map(|(value, capability)| {
            value
                .stored(&self.data_key)
                .map(|evidence| IssuedOpenid4vpVerificationEvidence {
                    evidence,
                    capability,
                })
        })
        .transpose()
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
            "SELECT id, tenant_id, verification_run_jti, verification_artifact_sha256, \
                 verification_matrix_sha256, verification_suite_plan_id, \
                 verification_suite_module_id, verification_test_name, \
                 verification_variant_sha256, verification_context_sha256, \
                 verification_intent_jws, verification_presentation_request_sha256, \
                 openid4vc_trust_policy_binding_id, openid4vc_trust_policy_resource_id, \
                 openid4vc_trust_policy_digest, result_ciphertext, completed_at, \
                 verification_issuance_expires_at AS expires_at \
             FROM openid4vp_transactions \
             WHERE id = $1 AND tenant_id = $2 AND completed_at IS NOT NULL \
               AND result_ciphertext IS NOT NULL \
               AND verification_issuance_expires_at > $3 \
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
        clear_expired_verification_evidence(
            &mut connection,
            self.tenant_id,
            capability_sha256,
            now,
        )
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
        idempotency: PresentationCreateIdempotency<'_>,
    ) -> Result<PresentationCreateOutcome, PresentationStoreError> {
        validate_create_idempotency(idempotency)?;
        let mut connection = self
            .pool
            .get()
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        clear_expired_create_request(
            &mut connection,
            self.tenant_id,
            idempotency.request_jti,
            Utc::now(),
        )
        .await
        .map_err(|_| PresentationStoreError::Unavailable)?;
        cleanup_expired_transactions(&mut connection)
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
        let state_hash = blake3::hash(transaction.request.state.as_bytes())
            .to_hex()
            .to_string();
        let protected_private_key = transaction
            .response_encryption_private_key
            .as_deref()
            .map(|key| {
                protect_payload(
                    &self.data_key,
                    b"nazo-openid4vp-ephemeral-v2",
                    self.tenant_id,
                    transaction.id,
                    None,
                    key,
                )
            })
            .transpose()?;
        let inserted = sql_query(
            "INSERT INTO openid4vp_transactions \
             (id, tenant_id, client_id_prefix, request_method, response_mode, \
              wallet_authorization_endpoint, state_hash, request, request_object, request_uri, \
              openid4vc_trust_policy_binding_id, openid4vc_trust_policy_resource_id, \
              openid4vc_trust_policy_digest, ephemeral_private_key_ciphertext, expires_at, \
              create_request_jti, create_request_sha256, create_request_canonical_json) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) \
             ON CONFLICT (tenant_id, create_request_jti) \
                 WHERE create_request_jti IS NOT NULL DO NOTHING",
        )
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
        .bind::<sql_types::Text, _>(idempotency.request_jti)
        .bind::<sql_types::Text, _>(idempotency.request_sha256)
        .bind::<sql_types::Text, _>(idempotency.canonical_request)
        .execute(&mut connection)
        .await
        .map_err(|error| match error {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _,
            ) => PresentationStoreError::Unavailable,
            _ => PresentationStoreError::Unavailable,
        })?;
        match inserted {
            1 => Ok(PresentationCreateOutcome::Created),
            0 => self
                .load_idempotent_create(&mut connection, idempotency)
                .await?
                .map(PresentationCreateOutcome::Existing)
                .ok_or(PresentationStoreError::InvalidTransition),
            _ => Err(PresentationStoreError::InvalidTransition),
        }
    }

    async fn load_idempotent_create(
        &self,
        connection: &mut diesel_async::AsyncPgConnection,
        idempotency: PresentationCreateIdempotency<'_>,
    ) -> Result<Option<PresentationTransaction>, PresentationStoreError> {
        validate_create_idempotency(idempotency)?;
        let row = load_presentation_by_create_request(
            connection,
            self.tenant_id,
            idempotency.request_jti,
        )
        .await
        .map_err(|_| PresentationStoreError::Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if row.create_request_sha256.as_deref() != Some(idempotency.request_sha256)
            || row.create_request_canonical_json.as_deref() != Some(idempotency.canonical_request)
        {
            return Err(PresentationStoreError::IdempotencyConflict);
        }
        row.transaction().map(Some)
    }
}

impl PresentationStorePort for Openid4vpRepository {
    fn create<'a>(
        &'a self,
        transaction: &'a PresentationTransaction,
        idempotency: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<PresentationCreateOutcome, PresentationStoreError>>
    {
        Box::pin(async move { self.create_inner(transaction, idempotency).await })
    }

    fn find_by_create_request<'a>(
        &'a self,
        idempotency: PresentationCreateIdempotency<'a>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async move {
            let mut connection = self
                .pool
                .get()
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            clear_expired_create_request(
                &mut connection,
                self.tenant_id,
                idempotency.request_jti,
                Utc::now(),
            )
            .await
            .map_err(|_| PresentationStoreError::Unavailable)?;
            cleanup_expired_transactions(&mut connection)
                .await
                .map_err(|_| PresentationStoreError::Unavailable)?;
            self.load_idempotent_create(&mut connection, idempotency)
                .await
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
            row.map(|value| value.transaction_with_key(&self.data_key, self.tenant_id, now))
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
            row.transaction_with_key(&self.data_key, self.tenant_id, now)
                .map(Some)
        })
    }

    fn complete<'a>(
        &'a self,
        transaction_id: Uuid,
        state_hash: &'a str,
        result: &'a PresentationResult,
        verification_binding: Option<nazo_openid4vp::PresentationCompletionBinding<'a>>,
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
            let intent_sha256 = verification_binding
                .map(|binding| nazo_operator_protocol::compact_sha256(binding.intent_jws));
            let payload_binding = verification_binding.zip(intent_sha256.as_deref()).map(
                |(binding, intent_sha256)| PayloadVerificationBinding {
                    context_sha256: binding.context_sha256,
                    presentation_request_sha256: binding.presentation_request_sha256,
                    intent_sha256,
                    trust_policy_binding_id: binding.trust_policy_binding_id,
                    trust_policy_resource_id: binding.trust_policy_resource_id,
                    trust_policy_digest: binding.trust_policy_digest,
                    issuance_request_jti: None,
                },
            );
            let encoded = protect_payload(
                &self.data_key,
                b"nazo-openid4vp-result-v2",
                self.tenant_id,
                transaction_id,
                payload_binding,
                &encoded,
            )?;
            let changed = sql_query(
                "UPDATE openid4vp_transactions SET result_ciphertext = $5, completed_at = $4, \
                     ephemeral_private_key_ciphertext = NULL, \
                     verification_issuance_expires_at = CASE WHEN $6 IS NULL THEN NULL \
                         ELSE $4 + INTERVAL '600 seconds' END \
                 WHERE id = $1 AND tenant_id = $2 AND state_hash = $3 \
                   AND completed_at IS NULL AND expires_at > $4 \
                   AND ( \
                       ($6 IS NULL AND $7 IS NULL AND $8 IS NULL \
                           AND verification_context_sha256 IS NULL \
                           AND verification_intent_jws IS NULL \
                           AND verification_presentation_request_sha256 IS NULL) \
                       OR ($6 IS NOT NULL AND $7 IS NOT NULL AND $8 IS NOT NULL \
                           AND verification_context_sha256 = $6 \
                           AND verification_intent_jws = $7 \
                           AND verification_presentation_request_sha256 = $8 \
                           AND openid4vc_trust_policy_binding_id IS NOT DISTINCT FROM $9 \
                           AND openid4vc_trust_policy_resource_id IS NOT DISTINCT FROM $10 \
                           AND openid4vc_trust_policy_digest IS NOT DISTINCT FROM $11) \
                   ) \
                   AND openid4vc_presentation_trust_policy_is_active( \
                       tenant_id, openid4vc_trust_policy_binding_id, \
                       openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)",
            )
            .bind::<sql_types::Uuid, _>(transaction_id)
            .bind::<sql_types::Uuid, _>(self.tenant_id)
            .bind::<sql_types::Text, _>(state_hash)
            .bind::<sql_types::Timestamptz, _>(now)
            .bind::<sql_types::Binary, _>(encoded)
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                verification_binding.map(|binding| binding.context_sha256),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                verification_binding.map(|binding| binding.intent_jws),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                verification_binding.map(|binding| binding.presentation_request_sha256),
            )
            .bind::<sql_types::Nullable<sql_types::Uuid>, _>(
                verification_binding.and_then(|binding| binding.trust_policy_binding_id),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                verification_binding.and_then(|binding| binding.trust_policy_resource_id),
            )
            .bind::<sql_types::Nullable<sql_types::Text>, _>(
                verification_binding.and_then(|binding| binding.trust_policy_digest),
            )
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
            row.map(|value| value.stored(&self.data_key, self.tenant_id, now))
                .transpose()
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
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    create_request_jti: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    create_request_sha256: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    create_request_canonical_json: Option<String>,
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
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_context_sha256: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_intent_jws: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_presentation_request_sha256: Option<String>,
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
struct CleanupResult {
    #[diesel(sql_type = sql_types::Integer)]
    deleted_transactions: i32,
}

#[derive(QueryableByName)]
struct VerificationEvidenceRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
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
    verification_presentation_request_sha256: String,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    openid4vc_trust_policy_binding_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_resource_id: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_digest: Option<String>,
    #[diesel(sql_type = sql_types::Text)]
    verification_capability_sha256: String,
    #[diesel(sql_type = sql_types::Binary)]
    verification_capability_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Text)]
    verification_issuance_request_jti: String,
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
    #[diesel(sql_type = sql_types::Uuid)]
    tenant_id: Uuid,
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
    verification_presentation_request_sha256: String,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    openid4vc_trust_policy_binding_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_resource_id: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_digest: Option<String>,
    #[diesel(sql_type = sql_types::Binary)]
    result_ciphertext: Vec<u8>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    completed_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

fn validated_verification_context(
    context: nazo_operator_protocol::Openid4vpEvidenceContext,
    expected_sha256: &str,
) -> Result<(nazo_operator_protocol::Openid4vpEvidenceContext, String), PresentationStoreError> {
    let actual_sha256 =
        nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(&context)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
    if actual_sha256 != expected_sha256 {
        return Err(PresentationStoreError::InvalidTransition);
    }
    Ok((context, actual_sha256))
}

impl VerificationIntentRow {
    fn prepared(
        &self,
        data_key: &[u8; 32],
    ) -> Result<PreparedOpenid4vpVerificationEvidence, PresentationStoreError> {
        let intent_sha256 = nazo_operator_protocol::compact_sha256(&self.verification_intent_jws);
        let result = unprotect_payload(
            data_key,
            b"nazo-openid4vp-result-v2",
            self.tenant_id,
            self.id,
            Some(PayloadVerificationBinding {
                context_sha256: &self.verification_context_sha256,
                presentation_request_sha256: &self.verification_presentation_request_sha256,
                intent_sha256: &intent_sha256,
                trust_policy_binding_id: self.openid4vc_trust_policy_binding_id,
                trust_policy_resource_id: self.openid4vc_trust_policy_resource_id.as_deref(),
                trust_policy_digest: self.openid4vc_trust_policy_digest.as_deref(),
                issuance_request_jti: None,
            }),
            &self.result_ciphertext,
            false,
        )?;
        let result: PresentationResult = serde_json::from_slice(&result)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        if result.transaction_id != self.id
            || result.completed_at.timestamp_micros() != self.completed_at.timestamp_micros()
        {
            return Err(PresentationStoreError::InvalidTransition);
        }
        let (context, digest) = validated_verification_context(
            nazo_operator_protocol::Openid4vpEvidenceContext {
                run_jti: self.verification_run_jti.clone(),
                artifact_sha256: self.verification_artifact_sha256.clone(),
                matrix_sha256: self.verification_matrix_sha256.clone(),
                suite_plan_id: self.verification_suite_plan_id.to_string(),
                suite_module_id: self.verification_suite_module_id.to_string(),
                test_name: self.verification_test_name.clone(),
                variant_sha256: self.verification_variant_sha256.clone(),
            },
            &self.verification_context_sha256,
        )?;
        let presentation_binding = nazo_operator_protocol::Openid4vpPresentationBinding {
            presentation_request_sha256: self.verification_presentation_request_sha256.clone(),
            trust_policy: nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                binding_id: self
                    .openid4vc_trust_policy_binding_id
                    .map(|value| value.to_string()),
                resource_id: self.openid4vc_trust_policy_resource_id.clone(),
                resource_digest: self.openid4vc_trust_policy_digest.clone(),
            },
        };
        nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
            &presentation_binding,
        )
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
        Ok(PreparedOpenid4vpVerificationEvidence {
            transaction_id: self.id,
            context,
            context_sha256: digest,
            intent_jws: self.verification_intent_jws.clone(),
            presentation_binding,
            completed_at: self.completed_at,
            issuance_expires_at: self.expires_at,
        })
    }
}

#[derive(QueryableByName)]
struct VerificationAttachmentRow {
    #[diesel(sql_type = sql_types::Uuid)]
    id: Uuid,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_run_jti: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_artifact_sha256: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_matrix_sha256: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    verification_suite_plan_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    verification_suite_module_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_test_name: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_variant_sha256: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_context_sha256: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_intent_jws: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    verification_presentation_request_sha256: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Uuid>)]
    openid4vc_trust_policy_binding_id: Option<Uuid>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_resource_id: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Text>)]
    openid4vc_trust_policy_digest: Option<String>,
    #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
    completed_at: Option<DateTime<Utc>>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    created_at: DateTime<Utc>,
    #[diesel(sql_type = sql_types::Timestamptz)]
    expires_at: DateTime<Utc>,
}

impl VerificationAttachmentRow {
    fn state(self) -> Result<Openid4vpVerificationAttachmentState, PresentationStoreError> {
        if self.completed_at.is_some() {
            return Ok(Openid4vpVerificationAttachmentState::Conflict);
        }
        let values = (
            self.verification_run_jti,
            self.verification_artifact_sha256,
            self.verification_matrix_sha256,
            self.verification_suite_plan_id,
            self.verification_suite_module_id,
            self.verification_test_name,
            self.verification_variant_sha256,
            self.verification_context_sha256,
            self.verification_intent_jws,
            self.verification_presentation_request_sha256,
        );
        match values {
            (None, None, None, None, None, None, None, None, None, None) => {
                Ok(Openid4vpVerificationAttachmentState::Pending {
                    transaction_id: self.id,
                    created_at: self.created_at,
                    expires_at: self.expires_at,
                })
            }
            (
                Some(run_jti),
                Some(artifact_sha256),
                Some(matrix_sha256),
                Some(suite_plan_id),
                Some(suite_module_id),
                Some(test_name),
                Some(variant_sha256),
                Some(context_sha256),
                Some(intent_jws),
                Some(presentation_request_sha256),
            ) => {
                let (context, context_sha256) = validated_verification_context(
                    nazo_operator_protocol::Openid4vpEvidenceContext {
                        run_jti,
                        artifact_sha256,
                        matrix_sha256,
                        suite_plan_id: suite_plan_id.to_string(),
                        suite_module_id: suite_module_id.to_string(),
                        test_name,
                        variant_sha256,
                    },
                    &context_sha256,
                )?;
                if intent_jws.is_empty()
                    || intent_jws.len() > nazo_operator_protocol::MAX_COMPACT_JWS_BYTES
                {
                    return Err(PresentationStoreError::InvalidTransition);
                }
                let presentation_binding = nazo_operator_protocol::Openid4vpPresentationBinding {
                    presentation_request_sha256,
                    trust_policy: nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                        binding_id: self
                            .openid4vc_trust_policy_binding_id
                            .map(|value| value.to_string()),
                        resource_id: self.openid4vc_trust_policy_resource_id,
                        resource_digest: self.openid4vc_trust_policy_digest,
                    },
                };
                nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
                    &presentation_binding,
                )
                .map_err(|_| PresentationStoreError::InvalidTransition)?;
                Ok(Openid4vpVerificationAttachmentState::Attached(
                    StoredOpenid4vpVerificationAttachment {
                        transaction_id: self.id,
                        context,
                        context_sha256,
                        intent_jws,
                        presentation_binding,
                        created_at: self.created_at,
                        expires_at: self.expires_at,
                    },
                ))
            }
            _ => Err(PresentationStoreError::InvalidTransition),
        }
    }

    fn attachment(self) -> Result<StoredOpenid4vpVerificationAttachment, PresentationStoreError> {
        match self.state()? {
            Openid4vpVerificationAttachmentState::Attached(attachment) => Ok(attachment),
            _ => Err(PresentationStoreError::InvalidTransition),
        }
    }
}

impl VerificationEvidenceRow {
    fn stored(
        self,
        data_key: &[u8; 32],
    ) -> Result<StoredOpenid4vpVerificationEvidence, PresentationStoreError> {
        let intent_sha256 = nazo_operator_protocol::compact_sha256(&self.verification_intent_jws);
        let result = unprotect_payload(
            data_key,
            b"nazo-openid4vp-result-v2",
            self.tenant_id,
            self.id,
            Some(PayloadVerificationBinding {
                context_sha256: &self.verification_context_sha256,
                presentation_request_sha256: &self.verification_presentation_request_sha256,
                intent_sha256: &intent_sha256,
                trust_policy_binding_id: self.openid4vc_trust_policy_binding_id,
                trust_policy_resource_id: self.openid4vc_trust_policy_resource_id.as_deref(),
                trust_policy_digest: self.openid4vc_trust_policy_digest.as_deref(),
                issuance_request_jti: None,
            }),
            &self.result_ciphertext,
            false,
        )?;
        let result: PresentationResult = serde_json::from_slice(&result)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
        if result.transaction_id != self.id
            || result.completed_at.timestamp_micros() != self.completed_at.timestamp_micros()
        {
            return Err(PresentationStoreError::InvalidTransition);
        }
        let (context, context_sha256) = validated_verification_context(
            nazo_operator_protocol::Openid4vpEvidenceContext {
                run_jti: self.verification_run_jti,
                artifact_sha256: self.verification_artifact_sha256,
                matrix_sha256: self.verification_matrix_sha256,
                suite_plan_id: self.verification_suite_plan_id.to_string(),
                suite_module_id: self.verification_suite_module_id.to_string(),
                test_name: self.verification_test_name,
                variant_sha256: self.verification_variant_sha256,
            },
            &self.verification_context_sha256,
        )?;
        let presentation_binding = nazo_operator_protocol::Openid4vpPresentationBinding {
            presentation_request_sha256: self.verification_presentation_request_sha256,
            trust_policy: nazo_operator_protocol::Openid4vpTrustPolicyBinding {
                binding_id: self
                    .openid4vc_trust_policy_binding_id
                    .map(|value| value.to_string()),
                resource_id: self.openid4vc_trust_policy_resource_id,
                resource_digest: self.openid4vc_trust_policy_digest,
            },
        };
        nazo_operator_protocol::canonical_openid4vp_presentation_binding_sha256(
            &presentation_binding,
        )
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
        Ok(StoredOpenid4vpVerificationEvidence {
            receipt_id: self.verification_receipt_id,
            transaction_id: self.id,
            context,
            capability_sha256: self.verification_capability_sha256,
            issuance_request_jti: self.verification_issuance_request_jti,
            intent_jws: self.verification_intent_jws,
            receipt_jws: self.verification_receipt_jws,
            presentation_binding,
            completed_at: self.completed_at,
            issued_at: self.verification_issued_at,
            expires_at: self.expires_at,
        })
    }
}

enum VerificationEvidenceLookup<'a> {
    CapabilitySha256(&'a str),
    TransactionId(Uuid),
}

async fn cleanup_expired_transactions(
    connection: &mut diesel_async::AsyncPgConnection,
) -> Result<(), diesel::result::Error> {
    let result =
        sql_query("SELECT nazo_openid4vp_cleanup_expired_transactions() AS deleted_transactions")
            .get_result::<CleanupResult>(connection)
            .await?;
    debug_assert!((0..=256).contains(&result.deleted_transactions));
    Ok(())
}

async fn clear_expired_create_request(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    request_jti: &str,
    now: DateTime<Utc>,
) -> Result<(), diesel::result::Error> {
    sql_query(
        "DELETE FROM openid4vp_transactions \
         WHERE tenant_id = $1 AND create_request_jti = $2 \
           AND GREATEST( \
               expires_at, \
               COALESCE(verification_issuance_expires_at, expires_at), \
               COALESCE(verification_expires_at, expires_at) \
           ) <= $3",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(request_jti)
    .bind::<sql_types::Timestamptz, _>(now)
    .execute(connection)
    .await?;
    Ok(())
}

async fn clear_expired_verification_evidence(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    capability_sha256: &str,
    now: DateTime<Utc>,
) -> Result<(), diesel::result::Error> {
    sql_query(
        "UPDATE openid4vp_transactions SET \
             verification_receipt_id = NULL, verification_issuance_request_jti = NULL, \
             verification_capability_sha256 = NULL, \
             verification_capability_ciphertext = NULL, verification_receipt_jws = NULL, \
             verification_issued_at = NULL, verification_expires_at = NULL \
         WHERE tenant_id = $1 AND verification_capability_sha256 = $2 \
           AND verification_expires_at <= $3",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(capability_sha256)
    .bind::<sql_types::Timestamptz, _>(now)
    .execute(connection)
    .await?;
    Ok(())
}

async fn load_verification_attachment(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    transaction_id: Uuid,
) -> Result<Option<VerificationAttachmentRow>, diesel::result::Error> {
    sql_query(
        "SELECT id, verification_run_jti, verification_artifact_sha256, \
             verification_matrix_sha256, verification_suite_plan_id, \
             verification_suite_module_id, verification_test_name, \
             verification_variant_sha256, verification_context_sha256, \
             verification_intent_jws, verification_presentation_request_sha256, \
             openid4vc_trust_policy_binding_id, openid4vc_trust_policy_resource_id, \
             openid4vc_trust_policy_digest, completed_at, created_at, expires_at \
         FROM openid4vp_transactions \
         WHERE tenant_id = $1 AND id = $2 \
           AND openid4vc_presentation_trust_policy_is_active( \
               tenant_id, openid4vc_trust_policy_binding_id, \
               openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest)",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Uuid, _>(transaction_id)
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
    let projection = "SELECT id, tenant_id, verification_receipt_id, verification_run_jti, \
         verification_artifact_sha256, verification_matrix_sha256, \
         verification_suite_plan_id, verification_suite_module_id, \
         verification_test_name, verification_variant_sha256, \
         verification_context_sha256, verification_intent_jws, \
         verification_presentation_request_sha256, \
         openid4vc_trust_policy_binding_id, openid4vc_trust_policy_resource_id, \
         openid4vc_trust_policy_digest, verification_capability_sha256, \
         verification_capability_ciphertext, verification_issuance_request_jti, \
         verification_receipt_jws, \
         result_ciphertext, completed_at, verification_issued_at, \
         verification_expires_at AS expires_at \
         FROM openid4vp_transactions";
    let suffix = " AND completed_at IS NOT NULL AND result_ciphertext IS NOT NULL \
         AND verification_receipt_id IS NOT NULL \
         AND verification_expires_at > $3 \
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
        VerificationEvidenceLookup::TransactionId(transaction_id) => sql_query(format!(
            "{projection} WHERE tenant_id = $1 AND id = $2{suffix}"
        ))
        .bind::<sql_types::Uuid, _>(tenant_id)
        .bind::<sql_types::Uuid, _>(transaction_id)
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
        tenant_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<PresentationTransaction, PresentationStoreError> {
        let allow_legacy = self.legacy_transaction_aad_eligible(now);
        let mut transaction = self.transaction()?;
        transaction.response_encryption_private_key = self
            .ephemeral_private_key_ciphertext
            .as_deref()
            .map(|value| {
                unprotect_payload(
                    data_key,
                    b"nazo-openid4vp-ephemeral-v2",
                    tenant_id,
                    self.id,
                    None,
                    value,
                    allow_legacy,
                )
            })
            .transpose()?;
        Ok(transaction)
    }
    fn stored(
        self,
        data_key: &[u8; 32],
        tenant_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<StoredPresentation, PresentationStoreError> {
        let legacy_aad_eligible = self.legacy_transaction_aad_eligible(now);
        let intent_sha256 = self
            .verification_intent_jws
            .as_deref()
            .map(nazo_operator_protocol::compact_sha256);
        let verification_binding = match (
            self.verification_context_sha256.as_deref(),
            self.verification_presentation_request_sha256.as_deref(),
            intent_sha256.as_deref(),
        ) {
            (Some(context_sha256), Some(presentation_request_sha256), Some(intent_sha256)) => {
                Some(PayloadVerificationBinding {
                    context_sha256,
                    presentation_request_sha256,
                    intent_sha256,
                    trust_policy_binding_id: self.openid4vc_trust_policy_binding_id,
                    trust_policy_resource_id: self.openid4vc_trust_policy_resource_id.as_deref(),
                    trust_policy_digest: self.openid4vc_trust_policy_digest.as_deref(),
                    issuance_request_jti: None,
                })
            }
            (None, None, None) => None,
            _ => return Err(PresentationStoreError::InvalidTransition),
        };
        let decrypted = self
            .result_ciphertext
            .as_deref()
            .map(|value| {
                unprotect_payload(
                    data_key,
                    b"nazo-openid4vp-result-v2",
                    tenant_id,
                    self.id,
                    verification_binding,
                    value,
                    legacy_aad_eligible,
                )
            })
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
            .map(|value| {
                unprotect_payload(
                    data_key,
                    b"nazo-openid4vp-ephemeral-v2",
                    tenant_id,
                    self.id,
                    None,
                    value,
                    legacy_aad_eligible,
                )
            })
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

    fn legacy_transaction_aad_eligible(&self, now: DateTime<Utc>) -> bool {
        self.create_request_jti.is_none()
            && self.create_request_sha256.is_none()
            && self.create_request_canonical_json.is_none()
            && self.verification_context_sha256.is_none()
            && self.verification_intent_jws.is_none()
            && self.verification_presentation_request_sha256.is_none()
            && self.expires_at > now
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
         create_request_jti, create_request_sha256, create_request_canonical_json, \
         request, request_object, request_uri, openid4vc_trust_policy_binding_id, \
         openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest, \
         verification_context_sha256, verification_intent_jws, \
         verification_presentation_request_sha256, \
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

async fn load_presentation_by_create_request(
    connection: &mut diesel_async::AsyncPgConnection,
    tenant_id: Uuid,
    request_jti: &str,
) -> Result<Option<PresentationRow>, diesel::result::Error> {
    sql_query(
        "SELECT id, client_id_prefix, request_method, response_mode, wallet_authorization_endpoint, \
         create_request_jti, create_request_sha256, create_request_canonical_json, \
         request, request_object, request_uri, openid4vc_trust_policy_binding_id, \
         openid4vc_trust_policy_resource_id, openid4vc_trust_policy_digest, \
         verification_context_sha256, verification_intent_jws, \
         verification_presentation_request_sha256, \
         ephemeral_private_key_ciphertext, result_ciphertext, completed_at, expires_at, created_at \
         FROM openid4vp_transactions WHERE tenant_id = $1 AND create_request_jti = $2",
    )
    .bind::<sql_types::Uuid, _>(tenant_id)
    .bind::<sql_types::Text, _>(request_jti)
    .get_result(connection)
    .await
    .optional()
}

fn validate_create_idempotency(
    idempotency: PresentationCreateIdempotency<'_>,
) -> Result<(), PresentationStoreError> {
    nazo_operator_protocol::validate_openid4vp_create_request_jti(idempotency.request_jti)
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
    if idempotency.request_sha256.len() != 64
        || !idempotency
            .request_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || idempotency.canonical_request.is_empty()
        || idempotency.canonical_request.len()
            > nazo_operator_protocol::MAX_OPENID4VP_NORMALIZED_CREATE_REQUEST_BYTES
    {
        return Err(PresentationStoreError::InvalidTransition);
    }
    let normalized: nazo_operator_protocol::Openid4vpNormalizedCreateRequest =
        serde_json::from_str(idempotency.canonical_request)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
    let (canonical, sha256) =
        nazo_operator_protocol::canonical_openid4vp_normalized_create_request(&normalized)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
    if canonical != idempotency.canonical_request || sha256 != idempotency.request_sha256 {
        return Err(PresentationStoreError::InvalidTransition);
    }
    Ok(())
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

#[derive(Clone, Copy)]
struct PayloadVerificationBinding<'a> {
    context_sha256: &'a str,
    presentation_request_sha256: &'a str,
    intent_sha256: &'a str,
    trust_policy_binding_id: Option<Uuid>,
    trust_policy_resource_id: Option<&'a str>,
    trust_policy_digest: Option<&'a str>,
    issuance_request_jti: Option<&'a str>,
}

fn payload_aad(
    domain: &[u8],
    tenant_id: Uuid,
    transaction_id: Uuid,
    verification_binding: Option<PayloadVerificationBinding<'_>>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(512);
    let trust_policy_binding_id = verification_binding
        .and_then(|binding| binding.trust_policy_binding_id)
        .map(|value| value.to_string());
    for value in [domain, tenant_id.as_bytes(), transaction_id.as_bytes()] {
        aad.extend_from_slice(&(value.len() as u64).to_be_bytes());
        aad.extend_from_slice(value);
    }
    if let Some(binding) = verification_binding {
        for value in [
            binding.context_sha256,
            binding.presentation_request_sha256,
            binding.intent_sha256,
            trust_policy_binding_id.as_deref().unwrap_or(""),
            binding.trust_policy_resource_id.unwrap_or(""),
            binding.trust_policy_digest.unwrap_or(""),
            binding.issuance_request_jti.unwrap_or(""),
        ] {
            aad.extend_from_slice(&(value.len() as u64).to_be_bytes());
            aad.extend_from_slice(value.as_bytes());
        }
    }
    aad
}

#[allow(clippy::too_many_arguments)]
fn protect_payload(
    key: &[u8; 32],
    domain: &[u8],
    tenant_id: Uuid,
    transaction_id: Uuid,
    verification_binding: Option<PayloadVerificationBinding<'_>>,
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
                    aad: &payload_aad(domain, tenant_id, transaction_id, verification_binding),
                },
            )
            .map_err(|_| PresentationStoreError::Unavailable)?,
    );
    Ok(protected)
}

fn protect_verification_capability(
    key: &[u8; 32],
    tenant_id: Uuid,
    transaction_id: Uuid,
    context_sha256: &str,
    intent_jws: &str,
    presentation_binding: &nazo_operator_protocol::Openid4vpPresentationBinding,
    issuance_request_jti: &str,
    capability: &str,
) -> Result<Vec<u8>, PresentationStoreError> {
    let intent_sha256 = nazo_operator_protocol::compact_sha256(intent_jws);
    let trust_policy_binding_id = presentation_binding
        .trust_policy
        .binding_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
    protect_payload(
        key,
        b"nazo-openid4vp-capability-v1",
        tenant_id,
        transaction_id,
        Some(PayloadVerificationBinding {
            context_sha256,
            presentation_request_sha256: &presentation_binding.presentation_request_sha256,
            intent_sha256: &intent_sha256,
            trust_policy_binding_id,
            trust_policy_resource_id: presentation_binding.trust_policy.resource_id.as_deref(),
            trust_policy_digest: presentation_binding.trust_policy.resource_digest.as_deref(),
            issuance_request_jti: Some(issuance_request_jti),
        }),
        capability.as_bytes(),
    )
}

fn validate_new_verification_attachment(
    evidence: &NewOpenid4vpVerificationAttachment<'_>,
) -> Result<(), PresentationStoreError> {
    let canonical =
        nazo_operator_protocol::canonical_openid4vp_evidence_context_sha256(evidence.context)
            .map_err(|_| PresentationStoreError::InvalidTransition)?;
    if canonical != evidence.context_sha256
        || evidence.intent_jws.is_empty()
        || evidence.intent_jws.len() > nazo_operator_protocol::MAX_COMPACT_JWS_BYTES
        || evidence.presentation_request_sha256.len() != 64
        || !evidence
            .presentation_request_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PresentationStoreError::InvalidTransition);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn unprotect_payload(
    key: &[u8; 32],
    domain: &[u8],
    tenant_id: Uuid,
    transaction_id: Uuid,
    verification_binding: Option<PayloadVerificationBinding<'_>>,
    protected: &[u8],
    allow_legacy_transaction_aad: bool,
) -> Result<Vec<u8>, PresentationStoreError> {
    let (nonce, ciphertext) = protected
        .split_at_checked(12)
        .ok_or(PresentationStoreError::InvalidTransition)?;
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PresentationStoreError::Unavailable)?;
    let aad = payload_aad(domain, tenant_id, transaction_id, verification_binding);
    match cipher.decrypt(
        nonce.into(),
        Payload {
            msg: ciphertext,
            aad: &aad,
        },
    ) {
        Ok(value) => Ok(value),
        Err(_) if allow_legacy_transaction_aad => cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: transaction_id.as_bytes(),
                },
            )
            .map_err(|_| PresentationStoreError::InvalidTransition),
        Err(_) => Err(PresentationStoreError::InvalidTransition),
    }
}

fn unprotect_verification_capability(
    key: &[u8; 32],
    tenant_id: Uuid,
    transaction_id: Uuid,
    context_sha256: &str,
    intent_jws: &str,
    presentation_binding: &nazo_operator_protocol::Openid4vpPresentationBinding,
    issuance_request_jti: &str,
    protected: &[u8],
) -> Result<String, PresentationStoreError> {
    let intent_sha256 = nazo_operator_protocol::compact_sha256(intent_jws);
    let trust_policy_binding_id = presentation_binding
        .trust_policy
        .binding_id
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|_| PresentationStoreError::InvalidTransition)?;
    let plaintext = unprotect_payload(
        key,
        b"nazo-openid4vp-capability-v1",
        tenant_id,
        transaction_id,
        Some(PayloadVerificationBinding {
            context_sha256,
            presentation_request_sha256: &presentation_binding.presentation_request_sha256,
            intent_sha256: &intent_sha256,
            trust_policy_binding_id,
            trust_policy_resource_id: presentation_binding.trust_policy.resource_id.as_deref(),
            trust_policy_digest: presentation_binding.trust_policy.resource_digest.as_deref(),
            issuance_request_jti: Some(issuance_request_jti),
        }),
        protected,
        false,
    )?;
    String::from_utf8(plaintext).map_err(|_| PresentationStoreError::InvalidTransition)
}
