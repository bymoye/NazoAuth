use super::super::super::configuration::StartupConfiguration;
use super::*;
use anyhow::Context as _;

pub(super) struct Openid4vcServices {
    pub(super) credential_issuer_endpoint: Option<web::Data<CredentialIssuerEndpoint>>,
    pub(super) credential_dataset_admin: Option<web::Data<CredentialDatasetAdminService>>,
    pub(super) presentation_endpoint: Option<web::Data<PresentationEndpoint>>,
    pub(super) client_attestation_validator: Option<Arc<Openid4vcClientAttestationValidator>>,
    pub(super) revocation_policy: Option<CertificateRevocationPolicy>,
}

pub(super) async fn build(
    startup: &StartupConfiguration,
    token_service: &web::Data<crate::http::token::ServerTokenService>,
    authorization_service: &web::Data<ServerAuthorizationService>,
    runtime_registry: Arc<ServerRuntimeModuleRegistry>,
    keyset: &nazo_key_management::KeyManager,
) -> anyhow::Result<Openid4vcServices> {
    let settings = startup.settings.as_ref();
    let persistence = startup.persistence.provider();
    let openid4vc_enabled =
        settings.modules.enable_openid4vci_issuer || settings.modules.enable_openid4vp_verifier;
    let data_key = openid4vc_enabled.then(|| {
        settings
            .openid4vc
            .data_encryption_key
            .expect("enabled OpenID4VC modules require a data encryption key")
    });
    let trust_policy_store = data_key.map(|key| persistence.openid4vc_trust_policies(key));
    let revocation_policy = if openid4vc_enabled {
        Some(super::super::super::background::load_revocation_policy(&settings.openid4vc).await?)
    } else {
        None
    };
    let openid4vc_crypto = if let Some(revocation_policy) = revocation_policy.as_ref() {
        let certificate_chain = tokio::fs::read(
            settings
                .openid4vc
                .signing_certificate_chain_file
                .as_ref()
                .expect("enabled OpenID4VC modules require a certificate chain"),
        )
        .await
        .with_context(|| {
            format!(
                "failed to read OpenID4VC signing certificate chain from {}",
                settings
                    .openid4vc
                    .signing_certificate_chain_file
                    .as_ref()
                    .expect("enabled OpenID4VC modules require a certificate chain")
                    .display()
            )
        })?;
        let trust_anchors_path = settings
            .openid4vc
            .trust_anchors_file
            .as_ref()
            .expect("enabled OpenID4VC modules require trust anchors");
        let trust_anchors = tokio::fs::read(trust_anchors_path).await.with_context(|| {
            format!(
                "failed to read OpenID4VC trust anchors from {}",
                trust_anchors_path.display()
            )
        })?;
        Some(
            Openid4vcCredentialCrypto::new_with_policies(
                keyset.clone(),
                &certificate_chain,
                &trust_anchors,
                nazo_digital_credentials::VcIssuerTrustPolicy::san_bound(),
                revocation_policy.clone(),
            )
            .with_context(|| {
                format!(
                    "failed to initialize OpenID4VC credential crypto from certificate chain {} and trust anchors {}",
                    settings
                        .openid4vc
                        .signing_certificate_chain_file
                        .as_ref()
                        .expect("enabled OpenID4VC modules require a certificate chain")
                        .display(),
                    trust_anchors_path.display()
                )
            })?,
        )
    } else {
        None
    };
    let static_client_attestation =
        settings
            .openid4vc
            .client_attestation_issuer
            .as_ref()
            .map(|issuer| {
                (
                    issuer.clone(),
                    settings
                        .openid4vc
                        .client_attestation_jwks
                        .clone()
                        .expect("configured client attestation requires trust keys"),
                )
            });
    let client_attestation_validator = settings
        .modules
        .enable_openid4vci_issuer
        .then(|| {
            Openid4vcClientAttestationValidator::with_trust_policies(
                static_client_attestation,
                trust_policy_store
                    .clone()
                    .expect("enabled OpenID4VCI requires a trust policy store"),
                settings.tenant.context.tenant_id.as_uuid(),
            )
            .map(Arc::new)
        })
        .transpose()?;
    let (credential_issuer_endpoint, credential_dataset_admin) =
        if settings.modules.enable_openid4vci_issuer {
            let data_key = data_key.expect("enabled OpenID4VCI requires a data encryption key");
            let issuance_store = persistence.openid4vci_store(data_key);
            let subject_store = persistence.openid4vc_subjects();
            let dataset_store = persistence.openid4vci_datasets(data_key);
            let proof_validator = Openid4vcProofValidator::new(
                settings
                    .openid4vc
                    .key_attestation_jwks
                    .clone()
                    .unwrap_or_else(|| serde_json::json!({"keys": []})),
            )?
            .with_trust_policies(
                trust_policy_store
                    .clone()
                    .expect("enabled OpenID4VCI requires a trust policy store"),
                settings.tenant.context.tenant_id.as_uuid(),
            );
            let operations = Arc::new(ServerCredentialIssuerOperations::new(
                issuance_store,
                subject_store,
                dataset_store,
                settings.tenant.context.tenant_id.as_uuid(),
                data_key,
                token_service.clone().into_inner(),
                authorization_service.clone().into_inner(),
                runtime_registry.clone(),
                openid4vc_crypto
                    .as_ref()
                    .expect("enabled OpenID4VCI requires crypto")
                    .clone(),
                proof_validator,
                client_attestation_validator.clone(),
                settings.endpoint.issuer.clone(),
                settings.openid4vc.credential_configurations.clone(),
                settings
                    .openid4vc
                    .deferred_credential_configurations
                    .clone(),
                settings.protocol.dpop_nonce_policy,
            )?);
            let trusted_proxy_cidrs = settings.endpoint.trusted_proxy_cidrs.clone();
            (
                Some(web::Data::new(
                    CredentialIssuerEndpoint::new(
                        operations.clone(),
                        settings
                            .openid4vc
                            .issuer_management_token
                            .clone()
                            .expect("enabled OpenID4VCI requires a management token")
                            .into_bytes(),
                    )
                    .with_client_certificate_extractor(move |request| {
                        crate::http::mtls::request_mtls_thumbprint(request, &trusted_proxy_cidrs)
                    }),
                )),
                Some(web::Data::new(CredentialDatasetAdminService::new(
                    operations,
                ))),
            )
        } else {
            (None, None)
        };
    let presentation_endpoint = if settings.modules.enable_openid4vp_verifier {
        let data_key = data_key.expect("enabled OpenID4VP requires a data encryption key");
        let presentation_store =
            persistence.openid4vp_store(settings.tenant.context.tenant_id.as_uuid(), data_key);
        Some(web::Data::new(PresentationEndpoint::new(
            Arc::new(ServerPresentationOperations::new(
                presentation_store,
                settings.tenant.context.tenant_id.as_uuid(),
                openid4vc_crypto
                    .as_ref()
                    .expect("enabled OpenID4VP requires crypto")
                    .clone(),
                runtime_registry,
                trust_policy_store.expect("enabled OpenID4VP requires a trust policy store"),
                PresentationVerifierConfig {
                    issuer: settings.endpoint.issuer.clone(),
                    wallet_origins: settings.openid4vc.wallet_authorization_origins.clone(),
                    transaction_ttl_seconds: settings.openid4vc.transaction_ttl_seconds,
                },
            )),
            settings
                .openid4vc
                .verifier_management_token
                .clone()
                .expect("enabled OpenID4VP requires a management token")
                .into_bytes(),
        )))
    } else {
        None
    };

    Ok(Openid4vcServices {
        credential_issuer_endpoint,
        credential_dataset_admin,
        presentation_endpoint,
        client_attestation_validator,
        revocation_policy,
    })
}
