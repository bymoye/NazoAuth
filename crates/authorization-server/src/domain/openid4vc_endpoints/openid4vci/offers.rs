use super::*;

impl ServerCredentialIssuerOperations {
    pub(super) fn offer_operation<'a>(
        &'a self,
        offer_id: &'a str,
    ) -> CredentialIssuerFuture<'a, Result<CredentialOffer, CredentialHttpError>> {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::ExistingTransaction) {
                return Err(vci_error(
                    404,
                    "invalid_request",
                    "Credential issuer is disabled.",
                ));
            }
            let id = Uuid::parse_str(offer_id).map_err(|_| {
                vci_error(404, "invalid_request", "Credential offer was not found.")
            })?;
            let stored = self
                .store
                .offer(self.tenant_id, id, Utc::now())
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential offer state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vci_error(404, "invalid_request", "Credential offer was not found.")
                })?;
            Ok(CredentialOffer {
                credential_issuer: self.issuer.clone(),
                credential_configuration_ids: stored.credential_configuration_ids,
                grants: Some(stored.grants),
            })
        })
    }

    pub(super) fn pre_authorized_token_operation<'a>(
        &'a self,
        request: PreAuthorizedTokenRequest,
    ) -> CredentialIssuerFuture<'a, Result<PreAuthorizedTokenResponse, CredentialHttpError>> {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::NewRequest) {
                return Err(vci_error(
                    503,
                    "temporarily_unavailable",
                    "Credential issuer is unavailable.",
                ));
            }
            let target_uris = token_endpoint_dpop_target_uris(&self.issuer, &request.request_url);
            let target_uri_refs = target_uris.iter().map(String::as_str).collect::<Vec<_>>();
            let dpop_jkt = validate_authorization_server_dpop(
                self.authorization.as_ref(),
                DpopProofRequest {
                    proof: request.dpop_proof.as_deref(),
                    method: "POST",
                    target_uris: &target_uri_refs,
                    access_token: None,
                    expected_jkt: None,
                },
                self.dpop_nonce_policy,
            )
            .await
            .map_err(|error| match error {
                DpopError::UseNonce(nonce) => CredentialHttpError {
                    status: 400,
                    error: "use_dpop_nonce",
                    description: "Credential issuer requires nonce in DPoP proof.",
                    dpop_nonce: Some(nonce),
                },
                DpopError::NonceStoreUnavailable => {
                    vci_error(503, "server_error", "DPoP nonce validation is unavailable.")
                }
                _ => vci_error(400, "invalid_dpop_proof", "DPoP proof is invalid."),
            })?;
            let attested = match (
                request.client_attestation.as_deref(),
                request.client_attestation_pop.as_deref(),
            ) {
                (None, None) => None,
                (Some(attestation), Some(proof)) => {
                    let validator = self.client_attestation.as_ref().ok_or_else(|| {
                        vci_error(
                            401,
                            "invalid_client_attestation",
                            "Client attestation is not configured.",
                        )
                    })?;
                    let validated = validator
                        .validate_for_client(
                            attestation,
                            proof,
                            &self.issuer,
                            Utc::now().timestamp(),
                        )
                        .await
                        .map_err(|_| {
                            vci_error(
                                401,
                                "invalid_client_attestation",
                                "Client attestation is invalid.",
                            )
                        })?;
                    if request
                        .client_id
                        .as_deref()
                        .is_some_and(|client_id| client_id != validated.client_id)
                    {
                        return Err(vci_error(
                            401,
                            "invalid_client_attestation",
                            "Client identity does not match the attestation.",
                        ));
                    }
                    let replay_key = format!("client-attestation:{}", validated.client_id);
                    let fresh = self
                        .authorization
                        .consume_private_key_jwt(
                            &replay_key,
                            &validated.replay_id,
                            validated.replay_ttl_seconds,
                        )
                        .await
                        .map_err(|_| {
                            vci_error(
                                503,
                                "server_error",
                                "Client attestation replay state is unavailable.",
                            )
                        })?;
                    if !fresh {
                        return Err(vci_error(
                            401,
                            "invalid_client_attestation",
                            "Client attestation proof was replayed.",
                        ));
                    }
                    Some(validated)
                }
                _ => {
                    return Err(vci_error(
                        400,
                        "invalid_request",
                        "Both client attestation headers are required.",
                    ));
                }
            };
            let client_id = attested
                .as_ref()
                .map(|attestation| attestation.client_id.as_str())
                .or(request.client_id.as_deref())
                .unwrap_or("pre-authorized-wallet");
            let authorization = self
                .store
                .consume_pre_authorized_offer(
                    self.tenant_id,
                    &blake3_hex(&request.pre_authorized_code),
                    request.tx_code.as_deref(),
                    client_id,
                    Utc::now(),
                )
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential offer state is unavailable.",
                    )
                })?
                .ok_or_else(|| {
                    vci_error(
                        400,
                        "invalid_grant",
                        "Pre-authorized code or transaction code is invalid.",
                    )
                })?;
            let authorization_details = authorization
                .configuration_ids
                .iter()
                .map(|id| openid4vci_authorization_detail(&self.issuer, id))
                .collect::<Vec<_>>();
            let issued = self
                .token_service
                .sign_access_token(nazo_auth::AccessTokenSignInput {
                    issuer: &self.issuer,
                    tenant_id: authorization.tenant_id,
                    subject: &authorization.subject_id.to_string(),
                    user_id: Some(authorization.subject_id),
                    subject_type: "user",
                    client_id,
                    audiences: std::slice::from_ref(&self.issuer),
                    scopes: &[],
                    authorization_details: &Value::Array(authorization_details.clone()),
                    userinfo_claims: &[],
                    userinfo_claim_requests: &[],
                    ttl_seconds: (authorization.expires_at - Utc::now()).num_seconds().max(1),
                    dpop_jkt: dpop_jkt.as_deref(),
                    mtls_x5t_s256: None,
                    actor: None,
                })
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential access token signing failed.",
                    )
                })?;
            // The pre-authorized offer is consumed before the JWT is signed.  Persist the
            // resulting grant before returning the bearer/DPoP token so every token delivered
            // by this endpoint is visible to the credential endpoint's revocation and
            // lifecycle checks.  A failed persistence write fails closed: the token is never
            // sent to the wallet.
            let token_id = Uuid::parse_str(&issued.jti).map_err(|_| {
                vci_error(
                    503,
                    "server_error",
                    "Credential access token identifier is invalid.",
                )
            })?;
            let expires_at =
                chrono::DateTime::from_timestamp(issued.expires_at, 0).ok_or_else(|| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential access token expiry is invalid.",
                    )
                })?;
            self.store
                .upsert_access(
                    &blake3_hex(&issued.token),
                    &CredentialAccess {
                        token_id,
                        tenant_id: authorization.tenant_id,
                        subject_id: authorization.subject_id,
                        client_id: client_id.to_owned(),
                        configuration_ids: authorization.configuration_ids.clone(),
                        credential_identifiers: authorization.credential_identifiers.clone(),
                        dpop_jkt: dpop_jkt.clone(),
                        expires_at,
                    },
                )
                .await
                .map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Credential access state is unavailable.",
                    )
                })?;
            Ok(PreAuthorizedTokenResponse {
                access_token: issued.token,
                token_type: if dpop_jkt.is_some() { "DPoP" } else { "Bearer" }.to_owned(),
                expires_in: (issued.expires_at - Utc::now().timestamp()).max(1) as u64,
                authorization_details,
            })
        })
    }

    pub(super) fn create_offer_operation<'a>(
        &'a self,
        request: CreateCredentialOfferRequest,
    ) -> CredentialIssuerFuture<'a, Result<CreateCredentialOfferResponse, CredentialHttpError>>
    {
        Box::pin(async move {
            if !self.enabled(nazo_auth::CapabilityAdmission::NewRequest) {
                return Err(vci_error(
                    503,
                    "temporarily_unavailable",
                    "Credential issuer is unavailable.",
                ));
            }
            if request.credential_configuration_ids.is_empty()
                || request.credential_configuration_ids.len() > 16
                || !request
                    .credential_configuration_ids
                    .iter()
                    .all(|id| self.configurations.contains_key(id))
            {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Credential offer configurations are invalid.",
                ));
            }
            let grant_types = request
                .grant_types
                .iter()
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            if grant_types.is_empty()
                || grant_types.len() != request.grant_types.len()
                || !grant_types.iter().all(|grant| {
                    matches!(
                        *grant,
                        "authorization_code" | nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT
                    )
                })
                || request.tx_code.is_some()
                    && !grant_types.contains(nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT)
            {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Credential offer grant types are invalid.",
                ));
            }
            let tenant = TenantId::new(self.tenant_id)
                .map_err(|_| vci_error(500, "server_error", "Credential tenant is invalid."))?;
            let subject = UserId::new(request.subject_id)
                .map_err(|_| vci_error(400, "invalid_request", "Credential subject is invalid."))?;
            if !self
                .users
                .is_active_by_tenant_id(tenant, subject)
                .await
                .map_err(|_| vci_error(503, "server_error", "Credential subject lookup failed."))?
            {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Credential subject is not active.",
                ));
            }
            for configuration_id in &request.credential_configuration_ids {
                let available = self
                    .datasets
                    .dataset(self.tenant_id, request.subject_id, configuration_id)
                    .await
                    .map_err(|_| {
                        vci_error(503, "server_error", "Credential dataset lookup failed.")
                    })?
                    .is_some();
                if !available {
                    return Err(vci_error(
                        400,
                        "invalid_request",
                        "Requested credential data is unavailable for the subject.",
                    ));
                }
            }
            if !(30..=600).contains(&request.expires_in) {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Credential offer lifetime must be between 30 and 600 seconds.",
                ));
            }
            if request.tx_code.as_ref().is_some_and(|code| {
                !(4..=32).contains(&code.len()) || code.chars().any(char::is_whitespace)
            }) {
                return Err(vci_error(
                    400,
                    "invalid_request",
                    "Transaction code is invalid.",
                ));
            }

            let issuer_state = grant_types
                .contains("authorization_code")
                .then(random_urlsafe_token);
            let pre_authorized_code = grant_types
                .contains(nazo_openid4vci::PRE_AUTHORIZED_CODE_GRANT)
                .then(random_urlsafe_token);
            let grants = CredentialOfferGrants::new(
                issuer_state
                    .as_ref()
                    .map(|issuer_state| AuthorizationCodeGrant {
                        issuer_state: Some(issuer_state.clone()),
                        authorization_server: Some(self.issuer.clone()),
                    }),
                pre_authorized_code
                    .as_ref()
                    .map(|pre_authorized_code| PreAuthorizedCodeGrant {
                        pre_authorized_code: pre_authorized_code.clone(),
                        tx_code: request.tx_code.as_ref().map(|code| TxCodeDescription {
                            input_mode: Some(
                                if code.chars().all(|value| value.is_ascii_digit()) {
                                    "numeric"
                                } else {
                                    "text"
                                }
                                .to_owned(),
                            ),
                            length: Some(code.len() as u16),
                            description: None,
                        }),
                        authorization_server: Some(self.issuer.clone()),
                    }),
            );
            let id = Uuid::now_v7();
            let offer = nazo_openid4vci::StoredCredentialOffer {
                id,
                tenant_id: self.tenant_id,
                subject_id: Some(request.subject_id),
                credential_configuration_ids: request.credential_configuration_ids,
                grants: grants.clone(),
                expires_at: Utc::now() + Duration::seconds(request.expires_in as i64),
            };
            let tx_code_hash = match request.tx_code {
                Some(code) => Some(hash_password_blocking_limited(code).await.map_err(|_| {
                    vci_error(
                        503,
                        "server_error",
                        "Transaction code hashing is unavailable.",
                    )
                })?),
                None => None,
            };
            let issuer_state_hash = issuer_state.as_deref().map(blake3_hex);
            let pre_authorized_code_hash = pre_authorized_code.as_deref().map(blake3_hex);
            self.store
                .insert_offer(
                    &offer,
                    issuer_state_hash.as_deref(),
                    pre_authorized_code_hash.as_deref(),
                    tx_code_hash.as_deref(),
                )
                .await
                .map_err(|_| {
                    vci_error(503, "server_error", "Credential offer persistence failed.")
                })?;
            let credential_offer_uri = format!("{}/openid4vci/offers/{id}", self.issuer);
            Ok(CreateCredentialOfferResponse {
                offer_id: id,
                credential_offer_uri,
                credential_offer: CredentialOffer {
                    credential_issuer: self.issuer.clone(),
                    credential_configuration_ids: offer.credential_configuration_ids,
                    grants: Some(grants),
                },
            })
        })
    }
}
