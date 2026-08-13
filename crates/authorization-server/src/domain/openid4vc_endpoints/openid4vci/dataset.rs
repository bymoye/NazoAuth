use super::*;

use std::{future::Future, pin::Pin};

use base64::Engine as _;
use nazo_openid4vci::CredentialDatasetPort;

const VCI_CREDENTIAL_IDENTIFIER_PREFIX: &str = "nazo-vci-";

pub(crate) fn openid4vci_authorization_detail(
    issuer: &str,
    credential_configuration_id: &str,
) -> Value {
    json!({
        "type": "openid_credential",
        "credential_configuration_id": credential_configuration_id,
        "credential_identifiers": [
            openid4vci_credential_identifier(credential_configuration_id).0
        ],
        "locations": [issuer],
    })
}

pub(crate) fn openid4vci_credential_identifier(
    credential_configuration_id: &str,
) -> nazo_openid4vci::CredentialIdentifier {
    nazo_openid4vci::CredentialIdentifier(format!(
        "{VCI_CREDENTIAL_IDENTIFIER_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_configuration_id)
    ))
}

pub(crate) fn openid4vci_configuration_id_from_identifier(
    identifier: &nazo_openid4vci::CredentialIdentifier,
) -> Option<String> {
    let encoded = identifier
        .0
        .strip_prefix(VCI_CREDENTIAL_IDENTIFIER_PREFIX)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    String::from_utf8(decoded).ok()
}

pub(crate) fn token_endpoint_dpop_target_uris(issuer: &str, request_url: &str) -> Vec<String> {
    let public = format!("{}/token", issuer.trim_end_matches('/'));
    let trusted_request_url = url::Url::parse(request_url).ok().and_then(|request| {
        let issuer = url::Url::parse(issuer).ok()?;
        (request.scheme() == issuer.scheme()
            && request.host_str() == issuer.host_str()
            && request.port_or_known_default() == issuer.port_or_known_default()
            && request.path() == "/token")
            .then(|| request_url.to_owned())
    });
    [Some(public), trusted_request_url]
        .into_iter()
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Clone)]
pub(super) struct Openid4vcDataset {
    pub(super) store: nazo_postgres::Openid4vciDatasetRepository,
}

impl CredentialDatasetPort for Openid4vcDataset {
    fn dataset<'a>(
        &'a self,
        access: &'a CredentialAccess,
        configuration_id: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Value, nazo_openid4vci::CredentialIssuanceError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.store
                .dataset(access.tenant_id, access.subject_id, configuration_id)
                .await
                .map_err(|_| nazo_openid4vci::CredentialIssuanceError::DatasetUnavailable)?
                .ok_or(nazo_openid4vci::CredentialIssuanceError::DatasetUnavailable)
        })
    }
}
