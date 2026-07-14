use chrono::Utc;
use nazo_auth::{
    AuthorizationFuture, AuthorizationPortError, AuthorizationResponseClaimsInput,
    AuthorizationResponseSignInput, AuthorizationResponseSignerPort, SigningPurpose,
    authorization_response_jwt_claims,
};
use serde_json::Value;

use crate::{KeyManager, signing_algorithm_from_name};

impl AuthorizationResponseSignerPort for KeyManager {
    fn sign_authorization_response<'a>(
        &'a self,
        input: AuthorizationResponseSignInput<'a>,
    ) -> AuthorizationFuture<'a, String> {
        Box::pin(async move {
            let claims = authorization_response_jwt_claims(
                input.issuer,
                &AuthorizationResponseClaimsInput {
                    client_id: input.client_id,
                    code: input.code,
                    error: input.error,
                    state: input.state,
                    ttl: input.ttl,
                },
                Utc::now().timestamp(),
            );
            let algorithm = match input.signing_algorithm {
                Some(name) => {
                    signing_algorithm_from_name(name).ok_or(AuthorizationPortError::Unexpected)?
                }
                None => self.snapshot().active_alg,
            };
            let mut header = jsonwebtoken::Header::new(algorithm);
            header.typ = Some("oauth-authz-resp+jwt".to_owned());
            self.encode_jwt(SigningPurpose::Jarm, &header, &Value::Object(claims))
                .await
                .map_err(|_| AuthorizationPortError::Unavailable)
        })
    }
}
