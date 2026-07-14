use nazo_auth::{BackchannelLogoutDelivery, RefreshToken};
use nazo_identity::ports::RepositoryError;

use crate::rows::auth::{BackchannelLogoutDeliveryRow, RefreshTokenRow};

impl TryFrom<RefreshTokenRow> for RefreshToken {
    type Error = RepositoryError;

    fn try_from(row: RefreshTokenRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            tenant_id: row.tenant_id,
            token_family_id: row.token_family_id,
            client_id: row.client_id,
            user_id: row.user_id,
            scopes: row.scopes,
            audience: row.audience,
            authorization_details: row.authorization_details,
            issued_at: row.issued_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
            subject: row.subject,
            dpop_jkt: row.dpop_jkt,
            mtls_x5t_s256: row.mtls_x5t_s256,
        })
    }
}

impl From<BackchannelLogoutDeliveryRow> for BackchannelLogoutDelivery {
    fn from(row: BackchannelLogoutDeliveryRow) -> Self {
        Self {
            id: row.id,
            logout_uri: row.logout_uri,
            logout_token: row.logout_token,
            attempts: row.attempts,
            expires_at: row.expires_at,
        }
    }
}
