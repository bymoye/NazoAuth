use super::*;

impl ServerCredentialIssuerOperations {
    pub(super) fn credential_operation<'a>(
        &'a self,
        context: CredentialRequestContext,
        body: CredentialRequestBody<CredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::NewRequest) {
                return Err(vci_error(
                    503,
                    "temporarily_unavailable",
                    "Credential issuer is not accepting new requests.",
                ));
            }
            let request = self.request_json(body).await?;
            let access = self.access(&context).await?;
            let request_digest = issuance_request_digest(
                "credential",
                &request,
                &context.request_url,
                context.method,
            )?;
            let issuance_id = stable_issuance_id(access.token_id, &request_digest);
            if let Some(response) = self
                .store
                .find_response(issuance_id, access.token_id, &request_digest, Utc::now())
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential issuance response state is unavailable.",
                    )
                })?
            {
                return response_from_record(response);
            }
            let dpop_nonce = self.next_dpop_nonce(&access).await?;
            let configuration_id = resolve_configuration_id(&request, &access)?;
            let configuration = self
                .configurations
                .get(&configuration_id)
                .cloned()
                .ok_or_else(|| {
                    vci_error(
                        400,
                        "unknown_credential_configuration",
                        "Credential configuration is unknown.",
                    )
                })?;
            let nonce = extract_proof_nonce(request.proofs.as_ref())
                .ok_or_else(|| vci_error(400, "invalid_proof", "Credential proof is missing."))?;
            let now = Utc::now();
            let disposition = if self.deferred_configurations.contains(&configuration_id) {
                IssuanceDisposition::Deferred {
                    ready_at: now + Duration::seconds(1),
                }
            } else {
                IssuanceDisposition::Immediate
            };
            let pending = self
                .service
                .issue_pending_with_identity(
                    &access,
                    &request,
                    &CredentialIssuance {
                        configuration_id,
                        configuration,
                        disposition,
                        status: None,
                        expires_at: now + Duration::days(365),
                    },
                    &nonce,
                    nazo_openid4vci::IssuanceIdentity {
                        issuance_id,
                        request_digest: request_digest.clone(),
                    },
                    now,
                )
                .await
                .map_err(map_issuance_error)?;
            let body = match self
                .finish_response(
                    pending.response.clone(),
                    request.credential_response_encryption.as_ref(),
                )
                .await
            {
                Ok(body) => body,
                Err(error) => {
                    let _ = self.service.rollback_pending(&pending, Utc::now()).await;
                    return Err(error);
                }
            };
            let response_record = stored_response(
                issuance_id,
                access.token_id,
                request_digest,
                &body,
                dpop_nonce.clone(),
                access.expires_at,
            )?;
            if let Err(error) = self
                .service
                .commit_pending_with_response(&pending, &response_record, Utc::now())
                .await
            {
                let _ = self.service.rollback_pending(&pending, Utc::now()).await;
                return Err(map_issuance_error(error));
            }
            Ok(CredentialEndpointResponse { body, dpop_nonce })
        })
    }

    pub(super) fn deferred_operation<'a>(
        &'a self,
        context: CredentialRequestContext,
        body: CredentialRequestBody<DeferredCredentialRequest>,
    ) -> CredentialIssuerFuture<
        'a,
        Result<CredentialEndpointResponse<CredentialResponseBody>, CredentialHttpError>,
    > {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::ExistingTransaction) {
                return Err(vci_error(
                    503,
                    "temporarily_unavailable",
                    "Credential issuer is unavailable.",
                ));
            }
            let request = self.request_json(body).await?;
            let access = self.access(&context).await?;
            let request_digest = issuance_request_digest(
                "deferred",
                &request,
                &context.request_url,
                context.method,
            )?;
            let issuance_id = stable_issuance_id(access.token_id, &request_digest);
            if let Some(response) = self
                .store
                .find_response(issuance_id, access.token_id, &request_digest, Utc::now())
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential issuance response state is unavailable.",
                    )
                })?
            {
                return response_from_record(response);
            }
            let dpop_nonce = self.next_dpop_nonce(&access).await?;
            let transaction_hash = blake3_hex(&request.transaction_id);
            let claim_id = Uuid::now_v7().to_string();
            let deferred = self
                .store
                .claim_ready_deferred(&transaction_hash, access.token_id, &claim_id, Utc::now())
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Deferred credential state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vci_error(
                        400,
                        "invalid_transaction_id",
                        "Deferred credential transaction is invalid or not ready.",
                    )
                })?
                .credential;
            let result = async {
                let payload: DeferredPayload = serde_json::from_slice(&deferred.payload_ciphertext)
                    .map_err(|_| {
                        vci_error(
                            503,
                            "server_error",
                            "Deferred credential payload is unavailable.",
                        )
                    })?;
                let configuration = self
                    .configurations
                    .get(&deferred.configuration_id)
                    .ok_or_else(|| {
                        vci_error(
                            503,
                            "server_error",
                            "Deferred credential configuration is unavailable.",
                        )
                    })?;
                let mut credentials = Vec::new();
                for holder_binding in deferred.holder_bindings {
                    let credential = self
                        .crypto
                        .sign(&nazo_digital_credentials::CredentialSignInput {
                            payload: nazo_digital_credentials::CredentialPayload {
                                issuer: self.issuer.clone(),
                                format: deferred.format,
                                configuration_id: deferred.configuration_id.clone(),
                                credential_type: configuration
                                    .vct
                                    .clone()
                                    .or_else(|| configuration.doctype.clone())
                                    .ok_or_else(|| {
                                        vci_error(
                                            503,
                                            "server_error",
                                            "Deferred credential type is unavailable.",
                                        )
                                    })?,
                                subject_claims: payload.dataset.clone(),
                                holder_binding: serde_json::from_value(holder_binding).ok(),
                                selectively_disclosable_claims: Vec::new(),
                            },
                            issued_at: payload.issued_at,
                            expires_at: payload.expires_at,
                            status: payload.status.clone(),
                        })
                        .await
                        .map_err(|_| {
                            vci_error(503, "server_error", "Deferred credential signing failed.")
                        })?;
                    credentials.push(nazo_openid4vci::IssuedCredential {
                        credential: Value::String(credential),
                    });
                }
                let notification_id = Uuid::now_v7().to_string();
                let notification_handle = nazo_openid4vci::NotificationHandle {
                    notification_id: notification_id.clone(),
                    token_id: access.token_id,
                    expires_at: access.expires_at.min(payload.expires_at),
                };
                // Finish response encoding before committing the lease. If
                // encryption fails, the transaction remains retryable.
                let body = self
                    .finish_response(
                        CredentialResponse {
                            credentials: Some(credentials),
                            transaction_id: None,
                            notification_id: Some(notification_id),
                            interval: None,
                        },
                        request.credential_response_encryption.as_ref(),
                    )
                    .await?;
                let response_record = stored_response(
                    issuance_id,
                    access.token_id,
                    request_digest.clone(),
                    &body,
                    dpop_nonce.clone(),
                    access.expires_at.min(payload.expires_at),
                )?;
                let committed = self
                    .store
                    .finalize_deferred_with_notification_and_response(
                        &transaction_hash,
                        access.token_id,
                        &claim_id,
                        &notification_handle,
                        &response_record,
                        Utc::now(),
                    )
                    .await
                    .map_err(|_| {
                        vci_error(
                            503,
                            "server_error",
                            "Deferred credential state is unavailable.",
                        )
                    })?;
                if !committed {
                    return Err(vci_error(
                        503,
                        "server_error",
                        "Deferred credential state transition was lost.",
                    ));
                }
                Ok(CredentialEndpointResponse { body, dpop_nonce })
            }
            .await;
            if result.is_err() {
                let _ = self
                    .store
                    .release_deferred(&transaction_hash, access.token_id, &claim_id, Utc::now())
                    .await;
            }
            result
        })
    }

    pub(super) fn notify_operation<'a>(
        &'a self,
        context: CredentialRequestContext,
        request: NotificationRequest,
    ) -> CredentialIssuerFuture<'a, Result<CredentialEndpointResponse<()>, CredentialHttpError>>
    {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::ExistingTransaction) {
                return Err(vci_error(
                    503,
                    "temporarily_unavailable",
                    "Credential issuer is unavailable.",
                ));
            }
            let access = self.access(&context).await?;
            let dpop_nonce = self.next_dpop_nonce(&access).await?;
            let recorded = self
                .store
                .record_notification(&IssuanceNotification {
                    notification_id: request.notification_id,
                    token_id: access.token_id,
                    event: request.event,
                    description: request.event_description,
                    occurred_at: Utc::now(),
                })
                .await
                .map_err(|_| {
                    vci_error(503, "server_error", "Notification state is unavailable.")
                })?;
            if !recorded {
                return Err(vci_error(
                    400,
                    "invalid_notification_id",
                    "Notification identifier is invalid or already terminal.",
                ));
            }
            Ok(CredentialEndpointResponse {
                body: (),
                dpop_nonce,
            })
        })
    }
}
