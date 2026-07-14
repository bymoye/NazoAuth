use chrono::{DateTime, Utc};
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, NullableExpressionMethods,
    OptionalExtension, PgTextExpressionMethods, QueryDsl,
};
use diesel_async::{AsyncConnection, RunQueryDsl};
use nazo_auth::{ApprovedClient, ValidatedClientRegistration};
use nazo_identity::{
    AccessRequest, AccessRequestPage, AccessRequestStatus, NewAccessRequest, TenantId, UserId,
    ports::RepositoryError,
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    DbPool,
    schema::{client_access_requests, oauth_clients, users},
};

#[derive(diesel::Queryable)]
struct AccessRequestRecord {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    requester_email: Option<String>,
    site_name: String,
    site_url: String,
    request_description: String,
    status: i16,
    admin_note: Option<String>,
    approved_client_id: Option<Uuid>,
    created_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
}

struct ClientInsertCommand<'a> {
    tenant: nazo_identity::TenantContext,
    registration: &'a ValidatedClientRegistration,
    client_secret_hash: Option<&'a str>,
    registration_access_token_blake3: Option<&'a str>,
}

macro_rules! user_record_selection {
    () => {
        (
            client_access_requests::id,
            client_access_requests::tenant_id,
            client_access_requests::user_id,
            diesel::dsl::sql::<diesel::sql_types::Nullable<diesel::sql_types::Text>>("NULL"),
            client_access_requests::site_name,
            client_access_requests::site_url,
            client_access_requests::request_description,
            client_access_requests::status,
            client_access_requests::admin_note,
            client_access_requests::approved_client_id,
            client_access_requests::created_at,
            client_access_requests::resolved_at,
        )
    };
}

macro_rules! admin_record_selection {
    () => {
        (
            client_access_requests::id,
            client_access_requests::tenant_id,
            client_access_requests::user_id,
            users::email.nullable(),
            client_access_requests::site_name,
            client_access_requests::site_url,
            client_access_requests::request_description,
            client_access_requests::status,
            client_access_requests::admin_note,
            client_access_requests::approved_client_id,
            client_access_requests::created_at,
            client_access_requests::resolved_at,
        )
    };
}

impl TryFrom<AccessRequestRecord> for AccessRequest {
    type Error = RepositoryError;

    fn try_from(record: AccessRequestRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            id: record.id,
            tenant_id: TenantId::new(record.tenant_id)
                .map_err(|error| RepositoryError::Consistency(error.to_string()))?,
            user_id: UserId::new(record.user_id)
                .map_err(|error| RepositoryError::Consistency(error.to_string()))?,
            requester_email: record.requester_email,
            site_name: record.site_name,
            site_url: record.site_url,
            request_description: record.request_description,
            status: AccessRequestStatus::from_code(record.status).ok_or_else(|| {
                RepositoryError::Consistency("invalid persisted access-request status".to_owned())
            })?,
            admin_note: record.admin_note,
            approved_client_id: record.approved_client_id,
            created_at: record.created_at,
            resolved_at: record.resolved_at,
        })
    }
}

#[derive(Clone)]
pub struct AccessRequestRepository {
    pool: DbPool,
}

impl AccessRequestRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn list_for_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> Result<Vec<AccessRequest>, RepositoryError> {
        let mut connection = self.connection().await?;
        client_access_requests::table
            .filter(client_access_requests::tenant_id.eq(tenant_id.as_uuid()))
            .filter(client_access_requests::user_id.eq(user_id.as_uuid()))
            .select(user_record_selection!())
            .order(client_access_requests::created_at.desc())
            .load::<AccessRequestRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(AccessRequest::try_from)
            .collect()
    }

    pub async fn create(
        &self,
        request: NewAccessRequest,
    ) -> Result<AccessRequest, RepositoryError> {
        let mut connection = self.connection().await?;
        let user_belongs_to_tenant = users::table
            .find(request.user_id.as_uuid())
            .filter(users::tenant_id.eq(request.tenant_id.as_uuid()))
            .select(users::id)
            .first::<Uuid>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .is_some();
        if !user_belongs_to_tenant {
            return Err(RepositoryError::NotFound);
        }
        diesel::insert_into(client_access_requests::table)
            .values((
                client_access_requests::tenant_id.eq(request.tenant_id.as_uuid()),
                client_access_requests::user_id.eq(request.user_id.as_uuid()),
                client_access_requests::site_name.eq(request.site_name),
                client_access_requests::site_url.eq(request.site_url),
                client_access_requests::request_description.eq(request.request_description),
                client_access_requests::status.eq(AccessRequestStatus::Pending.code()),
            ))
            .returning(user_record_selection!())
            .get_result::<AccessRequestRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .try_into()
    }

    pub async fn page(
        &self,
        tenant_id: TenantId,
        limit: i64,
        offset: i64,
        search: Option<&str>,
        status: Option<AccessRequestStatus>,
    ) -> Result<AccessRequestPage, RepositoryError> {
        let mut connection = self.connection().await?;
        let pattern = search_pattern(search);
        let mut count_query = client_access_requests::table
            .inner_join(
                users::table.on(users::id
                    .eq(client_access_requests::user_id)
                    .and(users::tenant_id.eq(client_access_requests::tenant_id))),
            )
            .filter(client_access_requests::tenant_id.eq(tenant_id.as_uuid()))
            .into_boxed();
        if let Some(status) = status {
            count_query = count_query.filter(client_access_requests::status.eq(status.code()));
        }
        if let Some(pattern) = &pattern {
            count_query = count_query.filter(
                users::email
                    .ilike(pattern.clone())
                    .or(client_access_requests::site_name.ilike(pattern.clone()))
                    .or(client_access_requests::site_url.ilike(pattern.clone())),
            );
        }
        let total = count_query
            .select(diesel::dsl::count(client_access_requests::id))
            .first(&mut connection)
            .await
            .map_err(map_error)?;

        let mut items_query = client_access_requests::table
            .inner_join(
                users::table.on(users::id
                    .eq(client_access_requests::user_id)
                    .and(users::tenant_id.eq(client_access_requests::tenant_id))),
            )
            .filter(client_access_requests::tenant_id.eq(tenant_id.as_uuid()))
            .into_boxed();
        if let Some(status) = status {
            items_query = items_query.filter(client_access_requests::status.eq(status.code()));
        }
        if let Some(pattern) = pattern {
            items_query = items_query.filter(
                users::email
                    .ilike(pattern.clone())
                    .or(client_access_requests::site_name.ilike(pattern.clone()))
                    .or(client_access_requests::site_url.ilike(pattern)),
            );
        }
        let items = items_query
            .select(admin_record_selection!())
            .order(client_access_requests::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<AccessRequestRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(AccessRequest::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AccessRequestPage { total, items })
    }

    pub async fn by_id(
        &self,
        tenant_id: TenantId,
        id: Uuid,
    ) -> Result<Option<AccessRequest>, RepositoryError> {
        let mut connection = self.connection().await?;
        client_access_requests::table
            .inner_join(
                users::table.on(users::id
                    .eq(client_access_requests::user_id)
                    .and(users::tenant_id.eq(client_access_requests::tenant_id))),
            )
            .filter(client_access_requests::tenant_id.eq(tenant_id.as_uuid()))
            .filter(client_access_requests::id.eq(id))
            .select(admin_record_selection!())
            .first::<AccessRequestRecord>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(AccessRequest::try_from)
            .transpose()
    }

    pub async fn approved_delivery_matches(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        request_id: Uuid,
        approved_client_id: Uuid,
        client_id: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        client_access_requests::table
            .inner_join(
                oauth_clients::table.on(oauth_clients::id
                    .nullable()
                    .eq(client_access_requests::approved_client_id)
                    .and(oauth_clients::tenant_id.eq(client_access_requests::tenant_id))),
            )
            .filter(client_access_requests::tenant_id.eq(tenant_id.as_uuid()))
            .filter(client_access_requests::user_id.eq(user_id.as_uuid()))
            .filter(client_access_requests::id.eq(request_id))
            .filter(client_access_requests::status.eq(AccessRequestStatus::Approved.code()))
            .filter(client_access_requests::approved_client_id.eq(Some(approved_client_id)))
            .filter(oauth_clients::id.eq(approved_client_id))
            .filter(oauth_clients::client_id.eq(client_id))
            .filter(oauth_clients::is_active.eq(true))
            .select(diesel::dsl::count_star())
            .first::<i64>(&mut connection)
            .await
            .map(|count| count == 1)
            .map_err(map_error)
    }

    pub async fn approve(
        &self,
        tenant: nazo_identity::TenantContext,
        request_id: Uuid,
        actor_user_id: UserId,
        client: &ValidatedClientRegistration,
        client_secret_hash: Option<&str>,
        registration_access_token_blake3: Option<&str>,
    ) -> Result<ApprovedClient, RepositoryError> {
        let mut connection = self.connection().await?;
        connection
            .transaction::<ApprovedClient, ApprovalError, _>(async |connection| {
                let pending = client_access_requests::table
                    .filter(client_access_requests::tenant_id.eq(tenant.tenant_id.as_uuid()))
                    .filter(client_access_requests::id.eq(request_id))
                    .filter(client_access_requests::status.eq(AccessRequestStatus::Pending.code()))
                    .select(client_access_requests::user_id)
                    .for_update()
                    .first::<Uuid>(connection)
                    .await
                    .optional()
                    .map_err(map_error)?;
                let Some(request_user_id) = pending else {
                    return Err(ApprovalError::Repository(RepositoryError::AlreadyProcessed));
                };
                for user_id in [request_user_id, actor_user_id.as_uuid()] {
                    let consistent = users::table
                        .find(user_id)
                        .filter(users::tenant_id.eq(tenant.tenant_id.as_uuid()))
                        .filter(users::realm_id.eq(tenant.realm_id.as_uuid()))
                        .filter(users::organization_id.eq(tenant.organization_id.as_uuid()))
                        .select(users::id)
                        .first::<Uuid>(connection)
                        .await
                        .optional()
                        .map_err(map_error)?
                        .is_some();
                    if !consistent {
                        return Err(ApprovalError::Repository(RepositoryError::Consistency(
                            "access-request user context is inconsistent".to_owned(),
                        )));
                    }
                }
                let approved = insert_client(
                    connection,
                    ClientInsertCommand {
                        tenant,
                        registration: client,
                        client_secret_hash,
                        registration_access_token_blake3,
                    },
                )
                .await?;
                let updated = diesel::update(
                    client_access_requests::table
                        .filter(client_access_requests::tenant_id.eq(tenant.tenant_id.as_uuid()))
                        .filter(client_access_requests::id.eq(request_id))
                        .filter(
                            client_access_requests::status.eq(AccessRequestStatus::Pending.code()),
                        ),
                )
                .set((
                    client_access_requests::status.eq(AccessRequestStatus::Approved.code()),
                    client_access_requests::resolved_by_user_id.eq(actor_user_id.as_uuid()),
                    client_access_requests::approved_client_id.eq(approved.id),
                    client_access_requests::resolved_at.eq(diesel::dsl::now),
                    client_access_requests::updated_at.eq(diesel::dsl::now),
                ))
                .execute(connection)
                .await
                .map_err(map_error)?;
                if updated != 1 {
                    return Err(ApprovalError::Repository(RepositoryError::AlreadyProcessed));
                }
                Ok(approved)
            })
            .await
            .map_err(ApprovalError::into_repository)
    }

    pub async fn reject(
        &self,
        tenant_id: TenantId,
        request_id: Uuid,
        actor_user_id: UserId,
        admin_note: String,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let updated = diesel::update(
            client_access_requests::table
                .filter(client_access_requests::tenant_id.eq(tenant_id.as_uuid()))
                .filter(client_access_requests::id.eq(request_id))
                .filter(client_access_requests::status.eq(AccessRequestStatus::Pending.code())),
        )
        .set((
            client_access_requests::status.eq(AccessRequestStatus::Rejected.code()),
            client_access_requests::admin_note.eq(admin_note),
            client_access_requests::resolved_by_user_id.eq(actor_user_id.as_uuid()),
            client_access_requests::resolved_at.eq(diesel::dsl::now),
            client_access_requests::updated_at.eq(diesel::dsl::now),
        ))
        .execute(&mut connection)
        .await
        .map_err(map_error)?;
        if updated == 1 {
            Ok(())
        } else {
            Err(RepositoryError::Conflict)
        }
    }

    pub async fn cancel_pending(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        request_id: Uuid,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        let deleted = diesel::delete(
            client_access_requests::table
                .filter(client_access_requests::tenant_id.eq(tenant_id.as_uuid()))
                .filter(client_access_requests::user_id.eq(user_id.as_uuid()))
                .filter(client_access_requests::id.eq(request_id))
                .filter(client_access_requests::status.eq(AccessRequestStatus::Pending.code())),
        )
        .execute(&mut connection)
        .await
        .map_err(map_error)?;
        if deleted == 1 {
            Ok(())
        } else {
            Err(RepositoryError::Conflict)
        }
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

impl nazo_identity::ports::AccessRequestRepositoryPort for AccessRequestRepository {
    fn list_for_user(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<AccessRequest>> {
        Box::pin(
            async move { AccessRequestRepository::list_for_user(self, tenant_id, user_id).await },
        )
    }

    fn create(
        &self,
        request: NewAccessRequest,
    ) -> nazo_identity::ports::RepositoryFuture<'_, AccessRequest> {
        Box::pin(async move { AccessRequestRepository::create(self, request).await })
    }

    fn approved_delivery_matches<'a>(
        &'a self,
        tenant_id: TenantId,
        user_id: UserId,
        request_id: Uuid,
        approved_client_id: Uuid,
        client_id: &'a str,
    ) -> nazo_identity::ports::RepositoryFuture<'a, bool> {
        Box::pin(async move {
            AccessRequestRepository::approved_delivery_matches(
                self,
                tenant_id,
                user_id,
                request_id,
                approved_client_id,
                client_id,
            )
            .await
        })
    }
}

async fn insert_client(
    connection: &mut diesel_async::AsyncPgConnection,
    command: ClientInsertCommand<'_>,
) -> Result<ApprovedClient, RepositoryError> {
    let prepared = command.registration;
    diesel::insert_into(oauth_clients::table)
        .values((
            oauth_clients::tenant_id.eq(command.tenant.tenant_id.as_uuid()),
            oauth_clients::realm_id.eq(command.tenant.realm_id.as_uuid()),
            oauth_clients::organization_id.eq(command.tenant.organization_id.as_uuid()),
            oauth_clients::client_id.eq(&prepared.client_id),
            oauth_clients::client_name.eq(&prepared.client_name),
            oauth_clients::client_type.eq(&prepared.client_type),
            oauth_clients::client_secret_hash.eq(command.client_secret_hash),
            oauth_clients::registration_access_token_blake3
                .eq(command.registration_access_token_blake3),
            oauth_clients::redirect_uris.eq(json!(&prepared.redirect_uris)),
            oauth_clients::post_logout_redirect_uris.eq(json!(&prepared.post_logout_redirect_uris)),
            oauth_clients::scopes.eq(json!(&prepared.scopes)),
            oauth_clients::allowed_audiences.eq(json!(&prepared.allowed_audiences)),
            oauth_clients::grant_types.eq(json!(&prepared.grant_types)),
            oauth_clients::token_endpoint_auth_method.eq(&prepared.token_endpoint_auth_method),
            oauth_clients::subject_type.eq(&prepared.subject_type),
            oauth_clients::sector_identifier_uri.eq(&prepared.sector_identifier_uri),
            oauth_clients::sector_identifier_host.eq(&prepared.sector_identifier_host),
            oauth_clients::require_dpop_bound_tokens.eq(prepared.require_dpop_bound_tokens),
            oauth_clients::allow_client_assertion_audience_array
                .eq(prepared.allow_client_assertion_audience_array),
            oauth_clients::allow_client_assertion_endpoint_audience
                .eq(prepared.allow_client_assertion_endpoint_audience),
            oauth_clients::require_par_request_object.eq(prepared.require_par_request_object),
            oauth_clients::allow_authorization_code_without_pkce
                .eq(prepared.allow_authorization_code_without_pkce),
            oauth_clients::backchannel_logout_uri.eq(&prepared.backchannel_logout_uri),
            oauth_clients::backchannel_logout_session_required
                .eq(prepared.backchannel_logout_session_required),
            oauth_clients::frontchannel_logout_uri.eq(&prepared.frontchannel_logout_uri),
            oauth_clients::frontchannel_logout_session_required
                .eq(prepared.frontchannel_logout_session_required),
            oauth_clients::tls_client_auth_subject_dn.eq(&prepared.tls_client_auth_subject_dn),
            oauth_clients::tls_client_auth_cert_sha256.eq(&prepared.tls_client_auth_cert_sha256),
            oauth_clients::tls_client_auth_san_dns.eq(json!(&prepared.tls_client_auth_san_dns)),
            oauth_clients::tls_client_auth_san_uri.eq(json!(&prepared.tls_client_auth_san_uri)),
            oauth_clients::tls_client_auth_san_ip.eq(json!(&prepared.tls_client_auth_san_ip)),
            oauth_clients::tls_client_auth_san_email.eq(json!(&prepared.tls_client_auth_san_email)),
            oauth_clients::jwks.eq(&prepared.jwks),
            oauth_clients::introspection_encrypted_response_alg
                .eq(&prepared.introspection_encrypted_response_alg),
            oauth_clients::introspection_encrypted_response_enc
                .eq(&prepared.introspection_encrypted_response_enc),
            oauth_clients::userinfo_signed_response_alg.eq(&prepared.userinfo_signed_response_alg),
            oauth_clients::userinfo_encrypted_response_alg
                .eq(&prepared.userinfo_encrypted_response_alg),
            oauth_clients::userinfo_encrypted_response_enc
                .eq(&prepared.userinfo_encrypted_response_enc),
            oauth_clients::authorization_signed_response_alg
                .eq(&prepared.authorization_signed_response_alg),
            oauth_clients::authorization_encrypted_response_alg
                .eq(&prepared.authorization_encrypted_response_alg),
            oauth_clients::authorization_encrypted_response_enc
                .eq(&prepared.authorization_encrypted_response_enc),
            oauth_clients::is_active.eq(true),
        ))
        .returning((oauth_clients::id, oauth_clients::client_id))
        .get_result::<(Uuid, String)>(connection)
        .await
        .map(|(id, client_id)| ApprovedClient { id, client_id })
        .map_err(map_error)
}

fn search_pattern(search: Option<&str>) -> Option<String> {
    search
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| format!("%{value}%"))
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    match error {
        diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::UniqueViolation,
            _,
        ) => RepositoryError::Conflict,
        other => RepositoryError::Unexpected(other.to_string()),
    }
}

enum ApprovalError {
    Diesel(diesel::result::Error),
    Repository(RepositoryError),
}

impl ApprovalError {
    fn into_repository(self) -> RepositoryError {
        match self {
            Self::Diesel(error) => map_error(error),
            Self::Repository(error) => error,
        }
    }
}

impl From<diesel::result::Error> for ApprovalError {
    fn from(error: diesel::result::Error) -> Self {
        Self::Diesel(error)
    }
}

impl From<RepositoryError> for ApprovalError {
    fn from(error: RepositoryError) -> Self {
        Self::Repository(error)
    }
}

#[cfg(test)]
mod tests {
    use super::search_pattern;

    #[test]
    fn search_pattern_trims_and_ignores_blank_queries() {
        assert_eq!(search_pattern(None), None);
        assert_eq!(search_pattern(Some("")), None);
        assert_eq!(search_pattern(Some("   \t")), None);
        assert_eq!(
            search_pattern(Some("  alice@example.com  ")).as_deref(),
            Some("%alice@example.com%")
        );
    }
}
