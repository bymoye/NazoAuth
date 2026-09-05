use jsonwebtoken::Algorithm;
use nazo_auth::SigningPurpose;
use nazo_digital_credentials::{
    CredentialFormat, CredentialFuture, CredentialSignInput, CredentialSignerPort,
    CredentialTrustError,
};
use nazo_key_management::Openid4vcSigningLease;
use serde_json::Value;

use super::{Openid4vcCredentialCrypto, mdoc, sd_jwt};

impl Openid4vcCredentialCrypto {
    pub(crate) async fn sign_request_object(
        &self,
        lease: &Openid4vcSigningLease,
        claims: &Value,
    ) -> anyhow::Result<String> {
        let material = self.signing_material(lease)?;
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.typ = Some("oauth-authz-req+jwt".to_owned());
        header.x5c = Some(material.x5c);
        lease
            .encode_jwt(SigningPurpose::PresentationRequest, &header, claims)
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn sign_issuer_metadata(&self, claims: &Value) -> anyhow::Result<String> {
        let lease = self.prepare_signing()?;
        let material = self.signing_material(&lease)?;
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.typ = Some("openidvci-issuer-metadata+jwt".to_owned());
        header.x5c = Some(material.x5c);
        lease
            .encode_jwt(SigningPurpose::Credential, &header, claims)
            .await
            .map_err(Into::into)
    }
}

impl CredentialSignerPort for Openid4vcCredentialCrypto {
    fn sign<'a>(
        &'a self,
        input: &'a CredentialSignInput,
    ) -> CredentialFuture<'a, Result<String, CredentialTrustError>> {
        Box::pin(async move {
            match input.payload.format {
                CredentialFormat::SdJwtVc => sd_jwt::sign(self, input).await,
                CredentialFormat::MsoMdoc => mdoc::sign(self, input).await,
            }
        })
    }
}
