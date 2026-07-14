use chrono::{DateTime, Utc};
use diesel::{
    ExpressionMethods, JoinOnDsl, OptionalExtension, QueryDsl, SelectableHelper,
    TextExpressionMethods,
};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl};
use nazo_auth::{
    AdminClientFuture, AdminClientPortError, AdminClientRepositoryPort, LogoutClientRepositoryPort,
    LogoutDependencyError, LogoutFuture, OAuthClient, RegisteredLogoutClient,
    ValidatedClientRegistration,
};
use nazo_identity::ports::RepositoryError;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    DbPool,
    schema::{oauth_clients, oauth_tokens, user_client_grants},
};

#[derive(Clone, Debug, diesel::Queryable, diesel::Selectable)]
#[diesel(table_name = crate::schema::oauth_clients)]
struct OAuthClientRecord {
    id: Uuid,
    tenant_id: Uuid,
    realm_id: Uuid,
    organization_id: Uuid,
    client_id: String,
    client_name: String,
    client_type: String,
    redirect_uris: Value,
    scopes: Value,
    allowed_audiences: Value,
    grant_types: Value,
    token_endpoint_auth_method: String,
    require_dpop_bound_tokens: bool,
    require_mtls_bound_tokens: bool,
    tls_client_auth_subject_dn: Option<String>,
    tls_client_auth_cert_sha256: Option<String>,
    tls_client_auth_san_dns: Value,
    tls_client_auth_san_uri: Value,
    tls_client_auth_san_ip: Value,
    tls_client_auth_san_email: Value,
    allow_client_assertion_audience_array: bool,
    allow_client_assertion_endpoint_audience: bool,
    require_par_request_object: bool,
    allow_authorization_code_without_pkce: bool,
    is_active: bool,
    jwks: Option<Value>,
    introspection_encrypted_response_alg: Option<String>,
    introspection_encrypted_response_enc: Option<String>,
    userinfo_signed_response_alg: Option<String>,
    userinfo_encrypted_response_alg: Option<String>,
    userinfo_encrypted_response_enc: Option<String>,
    authorization_signed_response_alg: Option<String>,
    authorization_encrypted_response_alg: Option<String>,
    authorization_encrypted_response_enc: Option<String>,
    post_logout_redirect_uris: Value,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: bool,
    frontchannel_logout_uri: Option<String>,
    frontchannel_logout_session_required: bool,
    subject_type: String,
    sector_identifier_uri: Option<String>,
    sector_identifier_host: Option<String>,
}

#[derive(Clone)]
pub struct OAuthClientRepository {
    pool: DbPool,
}

impl OAuthClientRepository {
    #[must_use]
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn by_client_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> Result<Option<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(oauth_clients::client_id.eq(client_id))
            .select(OAuthClientRecord::as_select())
            .first::<OAuthClientRecord>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(OAuthClientRecord::into_domain)
            .transpose()
    }

    pub async fn by_id(&self, id: Uuid) -> Result<Option<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .find(id)
            .select(OAuthClientRecord::as_select())
            .first::<OAuthClientRecord>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(OAuthClientRecord::into_domain)
            .transpose()
    }

    pub async fn active_mtls_candidates(
        &self,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(
                oauth_clients::token_endpoint_auth_method
                    .eq_any(["tls_client_auth", "self_signed_tls_client_auth"]),
            )
            .filter(oauth_clients::client_type.eq("confidential"))
            .filter(oauth_clients::is_active.eq(true))
            .select(OAuthClientRecord::as_select())
            .limit(limit)
            .load::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(OAuthClientRecord::into_domain)
            .collect()
    }

    pub async fn page(
        &self,
        offset: i64,
        limit: i64,
    ) -> Result<(Vec<OAuthClient>, i64), RepositoryError> {
        let mut connection = self.connection().await?;
        let total = oauth_clients::table
            .count()
            .get_result::<i64>(&mut connection)
            .await
            .map_err(map_error)?;
        let clients = oauth_clients::table
            .select(OAuthClientRecord::as_select())
            .order(oauth_clients::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(OAuthClientRecord::into_domain)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((clients, total))
    }

    pub async fn insert(
        &self,
        client: &OAuthClient,
        client_secret_hash: Option<&str>,
        registration_access_token_blake3: Option<&str>,
    ) -> Result<OAuthClient, RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::insert_into(oauth_clients::table)
            .values((
                oauth_clients::id.eq(client.id),
                oauth_clients::tenant_id.eq(client.tenant_id),
                oauth_clients::realm_id.eq(client.realm_id),
                oauth_clients::organization_id.eq(client.organization_id),
                oauth_clients::client_id.eq(&client.client_id),
                oauth_clients::client_name.eq(&client.client_name),
                oauth_clients::client_type.eq(&client.client_type),
                oauth_clients::client_secret_hash.eq(client_secret_hash),
                oauth_clients::registration_access_token_blake3
                    .eq(registration_access_token_blake3),
                oauth_clients::redirect_uris.eq(serde_json::json!(&client.redirect_uris)),
                oauth_clients::post_logout_redirect_uris
                    .eq(serde_json::json!(&client.post_logout_redirect_uris)),
                oauth_clients::scopes.eq(serde_json::json!(&client.scopes)),
                oauth_clients::allowed_audiences.eq(serde_json::json!(&client.allowed_audiences)),
                oauth_clients::grant_types.eq(serde_json::json!(&client.grant_types)),
                oauth_clients::token_endpoint_auth_method.eq(&client.token_endpoint_auth_method),
                oauth_clients::subject_type.eq(&client.subject_type),
                oauth_clients::sector_identifier_uri.eq(&client.sector_identifier_uri),
                oauth_clients::sector_identifier_host.eq(&client.sector_identifier_host),
                oauth_clients::require_dpop_bound_tokens.eq(client.require_dpop_bound_tokens),
                oauth_clients::require_mtls_bound_tokens.eq(client.require_mtls_bound_tokens),
                oauth_clients::allow_client_assertion_audience_array
                    .eq(client.allow_client_assertion_audience_array),
                oauth_clients::allow_client_assertion_endpoint_audience
                    .eq(client.allow_client_assertion_endpoint_audience),
                oauth_clients::require_par_request_object.eq(client.require_par_request_object),
                oauth_clients::allow_authorization_code_without_pkce
                    .eq(client.allow_authorization_code_without_pkce),
                oauth_clients::backchannel_logout_uri.eq(&client.backchannel_logout_uri),
                oauth_clients::backchannel_logout_session_required
                    .eq(client.backchannel_logout_session_required),
                oauth_clients::frontchannel_logout_uri.eq(&client.frontchannel_logout_uri),
                oauth_clients::frontchannel_logout_session_required
                    .eq(client.frontchannel_logout_session_required),
                oauth_clients::tls_client_auth_subject_dn.eq(&client.tls_client_auth_subject_dn),
                oauth_clients::tls_client_auth_cert_sha256.eq(&client.tls_client_auth_cert_sha256),
                oauth_clients::tls_client_auth_san_dns
                    .eq(serde_json::json!(&client.tls_client_auth_san_dns)),
                oauth_clients::tls_client_auth_san_uri
                    .eq(serde_json::json!(&client.tls_client_auth_san_uri)),
                oauth_clients::tls_client_auth_san_ip
                    .eq(serde_json::json!(&client.tls_client_auth_san_ip)),
                oauth_clients::tls_client_auth_san_email
                    .eq(serde_json::json!(&client.tls_client_auth_san_email)),
                oauth_clients::jwks.eq(&client.jwks),
                oauth_clients::introspection_encrypted_response_alg
                    .eq(&client.introspection_encrypted_response_alg),
                oauth_clients::introspection_encrypted_response_enc
                    .eq(&client.introspection_encrypted_response_enc),
                oauth_clients::userinfo_signed_response_alg
                    .eq(&client.userinfo_signed_response_alg),
                oauth_clients::userinfo_encrypted_response_alg
                    .eq(&client.userinfo_encrypted_response_alg),
                oauth_clients::userinfo_encrypted_response_enc
                    .eq(&client.userinfo_encrypted_response_enc),
                oauth_clients::authorization_signed_response_alg
                    .eq(&client.authorization_signed_response_alg),
                oauth_clients::authorization_encrypted_response_alg
                    .eq(&client.authorization_encrypted_response_alg),
                oauth_clients::authorization_encrypted_response_enc
                    .eq(&client.authorization_encrypted_response_enc),
                oauth_clients::is_active.eq(client.is_active),
            ))
            .returning(OAuthClientRecord::as_returning())
            .get_result::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_domain()
    }

    pub async fn upsert(
        &self,
        client: &OAuthClient,
        client_secret_hash: Option<&str>,
    ) -> Result<(), RepositoryError> {
        let mut connection = self.connection().await?;
        upsert_client_on_connection(&mut connection, client, client_secret_hash)
            .await
            .map_err(map_error)
    }

    pub async fn update_metadata(
        &self,
        client: &OAuthClient,
    ) -> Result<OAuthClient, RepositoryError> {
        self.replace(client, None).await
    }

    async fn replace(
        &self,
        client: &OAuthClient,
        credentials: Option<(Option<&str>, Option<&str>)>,
    ) -> Result<OAuthClient, RepositoryError> {
        let mut connection = self.connection().await?;
        let target = oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(client.tenant_id))
            .filter(oauth_clients::id.eq(client.id));
        let metadata = (
            oauth_clients::client_name.eq(&client.client_name),
            oauth_clients::client_type.eq(&client.client_type),
            oauth_clients::redirect_uris.eq(serde_json::json!(&client.redirect_uris)),
            oauth_clients::post_logout_redirect_uris
                .eq(serde_json::json!(&client.post_logout_redirect_uris)),
            oauth_clients::scopes.eq(serde_json::json!(&client.scopes)),
            oauth_clients::allowed_audiences.eq(serde_json::json!(&client.allowed_audiences)),
            oauth_clients::grant_types.eq(serde_json::json!(&client.grant_types)),
            oauth_clients::token_endpoint_auth_method.eq(&client.token_endpoint_auth_method),
            oauth_clients::subject_type.eq(&client.subject_type),
            oauth_clients::sector_identifier_uri.eq(&client.sector_identifier_uri),
            oauth_clients::sector_identifier_host.eq(&client.sector_identifier_host),
            oauth_clients::require_dpop_bound_tokens.eq(client.require_dpop_bound_tokens),
            oauth_clients::require_mtls_bound_tokens.eq(client.require_mtls_bound_tokens),
            oauth_clients::allow_client_assertion_audience_array
                .eq(client.allow_client_assertion_audience_array),
            oauth_clients::allow_client_assertion_endpoint_audience
                .eq(client.allow_client_assertion_endpoint_audience),
            oauth_clients::require_par_request_object.eq(client.require_par_request_object),
            oauth_clients::allow_authorization_code_without_pkce
                .eq(client.allow_authorization_code_without_pkce),
            oauth_clients::backchannel_logout_uri.eq(&client.backchannel_logout_uri),
            oauth_clients::backchannel_logout_session_required
                .eq(client.backchannel_logout_session_required),
            oauth_clients::frontchannel_logout_uri.eq(&client.frontchannel_logout_uri),
            oauth_clients::frontchannel_logout_session_required
                .eq(client.frontchannel_logout_session_required),
            oauth_clients::tls_client_auth_subject_dn.eq(&client.tls_client_auth_subject_dn),
            oauth_clients::tls_client_auth_cert_sha256.eq(&client.tls_client_auth_cert_sha256),
            oauth_clients::tls_client_auth_san_dns
                .eq(serde_json::json!(&client.tls_client_auth_san_dns)),
            oauth_clients::tls_client_auth_san_uri
                .eq(serde_json::json!(&client.tls_client_auth_san_uri)),
            oauth_clients::tls_client_auth_san_ip
                .eq(serde_json::json!(&client.tls_client_auth_san_ip)),
            oauth_clients::tls_client_auth_san_email
                .eq(serde_json::json!(&client.tls_client_auth_san_email)),
            oauth_clients::jwks.eq(&client.jwks),
            oauth_clients::introspection_encrypted_response_alg
                .eq(&client.introspection_encrypted_response_alg),
            oauth_clients::introspection_encrypted_response_enc
                .eq(&client.introspection_encrypted_response_enc),
            oauth_clients::userinfo_signed_response_alg.eq(&client.userinfo_signed_response_alg),
            oauth_clients::userinfo_encrypted_response_alg
                .eq(&client.userinfo_encrypted_response_alg),
            oauth_clients::userinfo_encrypted_response_enc
                .eq(&client.userinfo_encrypted_response_enc),
            oauth_clients::authorization_signed_response_alg
                .eq(&client.authorization_signed_response_alg),
            oauth_clients::authorization_encrypted_response_alg
                .eq(&client.authorization_encrypted_response_alg),
            oauth_clients::authorization_encrypted_response_enc
                .eq(&client.authorization_encrypted_response_enc),
            oauth_clients::is_active.eq(client.is_active),
            oauth_clients::updated_at.eq(diesel::dsl::now),
        );
        let record = if let Some((secret_hash, access_token_hash)) = credentials {
            diesel::update(target)
                .set((
                    metadata,
                    oauth_clients::client_secret_hash.eq(secret_hash),
                    oauth_clients::registration_access_token_blake3.eq(access_token_hash),
                ))
                .returning(OAuthClientRecord::as_returning())
                .get_result::<OAuthClientRecord>(&mut connection)
                .await
        } else {
            diesel::update(target)
                .set(metadata)
                .returning(OAuthClientRecord::as_returning())
                .get_result::<OAuthClientRecord>(&mut connection)
                .await
        }
        .map_err(map_error)?;
        record.into_domain()
    }

    pub async fn replace_registration(
        &self,
        client: &OAuthClient,
        client_secret_hash: Option<&str>,
        registration_access_token_blake3: Option<&str>,
    ) -> Result<OAuthClient, RepositoryError> {
        let mut connection = self.connection().await?;
        let metadata = serde_json::json!({
            "client_name": client.client_name,
            "client_type": client.client_type,
            "redirect_uris": client.redirect_uris,
            "post_logout_redirect_uris": client.post_logout_redirect_uris,
            "scopes": client.scopes,
            "allowed_audiences": client.allowed_audiences,
            "grant_types": client.grant_types,
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
            "subject_type": client.subject_type,
            "sector_identifier_uri": client.sector_identifier_uri,
            "sector_identifier_host": client.sector_identifier_host,
            "require_dpop_bound_tokens": client.require_dpop_bound_tokens,
            "require_mtls_bound_tokens": client.require_mtls_bound_tokens,
            "allow_client_assertion_audience_array": client.allow_client_assertion_audience_array,
            "allow_client_assertion_endpoint_audience": client.allow_client_assertion_endpoint_audience,
            "require_par_request_object": client.require_par_request_object,
            "allow_authorization_code_without_pkce": client.allow_authorization_code_without_pkce,
            "backchannel_logout_uri": client.backchannel_logout_uri,
            "backchannel_logout_session_required": client.backchannel_logout_session_required,
            "frontchannel_logout_uri": client.frontchannel_logout_uri,
            "frontchannel_logout_session_required": client.frontchannel_logout_session_required,
            "tls_client_auth_subject_dn": client.tls_client_auth_subject_dn,
            "tls_client_auth_cert_sha256": client.tls_client_auth_cert_sha256,
            "tls_client_auth_san_dns": client.tls_client_auth_san_dns,
            "tls_client_auth_san_uri": client.tls_client_auth_san_uri,
            "tls_client_auth_san_ip": client.tls_client_auth_san_ip,
            "tls_client_auth_san_email": client.tls_client_auth_san_email,
            "jwks": client.jwks,
            "introspection_encrypted_response_alg": client.introspection_encrypted_response_alg,
            "introspection_encrypted_response_enc": client.introspection_encrypted_response_enc,
            "userinfo_signed_response_alg": client.userinfo_signed_response_alg,
            "userinfo_encrypted_response_alg": client.userinfo_encrypted_response_alg,
            "userinfo_encrypted_response_enc": client.userinfo_encrypted_response_enc,
            "authorization_signed_response_alg": client.authorization_signed_response_alg,
            "authorization_encrypted_response_alg": client.authorization_encrypted_response_alg,
            "authorization_encrypted_response_enc": client.authorization_encrypted_response_enc,
        });
        let changed = diesel::sql_query(
            r#"
            UPDATE oauth_clients SET
                client_name = $3->>'client_name',
                client_type = $3->>'client_type',
                client_secret_hash = $4,
                registration_access_token_blake3 = $5,
                redirect_uris = $3->'redirect_uris',
                post_logout_redirect_uris = $3->'post_logout_redirect_uris',
                scopes = $3->'scopes', allowed_audiences = $3->'allowed_audiences',
                grant_types = $3->'grant_types',
                token_endpoint_auth_method = $3->>'token_endpoint_auth_method',
                subject_type = $3->>'subject_type',
                sector_identifier_uri = $3->>'sector_identifier_uri',
                sector_identifier_host = $3->>'sector_identifier_host',
                require_dpop_bound_tokens = ($3->>'require_dpop_bound_tokens')::boolean,
                require_mtls_bound_tokens = ($3->>'require_mtls_bound_tokens')::boolean,
                allow_client_assertion_audience_array = ($3->>'allow_client_assertion_audience_array')::boolean,
                allow_client_assertion_endpoint_audience = ($3->>'allow_client_assertion_endpoint_audience')::boolean,
                require_par_request_object = ($3->>'require_par_request_object')::boolean,
                allow_authorization_code_without_pkce = ($3->>'allow_authorization_code_without_pkce')::boolean,
                backchannel_logout_uri = $3->>'backchannel_logout_uri',
                backchannel_logout_session_required = ($3->>'backchannel_logout_session_required')::boolean,
                frontchannel_logout_uri = $3->>'frontchannel_logout_uri',
                frontchannel_logout_session_required = ($3->>'frontchannel_logout_session_required')::boolean,
                tls_client_auth_subject_dn = $3->>'tls_client_auth_subject_dn',
                tls_client_auth_cert_sha256 = $3->>'tls_client_auth_cert_sha256',
                tls_client_auth_san_dns = $3->'tls_client_auth_san_dns',
                tls_client_auth_san_uri = $3->'tls_client_auth_san_uri',
                tls_client_auth_san_ip = $3->'tls_client_auth_san_ip',
                tls_client_auth_san_email = $3->'tls_client_auth_san_email',
                jwks = NULLIF($3->'jwks', 'null'::jsonb),
                introspection_encrypted_response_alg = $3->>'introspection_encrypted_response_alg',
                introspection_encrypted_response_enc = $3->>'introspection_encrypted_response_enc',
                userinfo_signed_response_alg = $3->>'userinfo_signed_response_alg',
                userinfo_encrypted_response_alg = $3->>'userinfo_encrypted_response_alg',
                userinfo_encrypted_response_enc = $3->>'userinfo_encrypted_response_enc',
                authorization_signed_response_alg = $3->>'authorization_signed_response_alg',
                authorization_encrypted_response_alg = $3->>'authorization_encrypted_response_alg',
                authorization_encrypted_response_enc = $3->>'authorization_encrypted_response_enc',
                updated_at = CURRENT_TIMESTAMP
            WHERE tenant_id = $1 AND id = $2 AND is_active = TRUE
            "#,
        )
        .bind::<diesel::sql_types::Uuid, _>(client.tenant_id)
        .bind::<diesel::sql_types::Uuid, _>(client.id)
        .bind::<diesel::sql_types::Jsonb, _>(&metadata)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(client_secret_hash)
        .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(registration_access_token_blake3)
        .execute(&mut connection)
        .await
        .map_err(map_error)?;
        if changed == 1 {
            Ok(client.clone())
        } else {
            Err(RepositoryError::NotFound)
        }
    }

    pub async fn rotate_credentials(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        client_secret_hash: Option<&str>,
        registration_access_token_blake3: &str,
    ) -> Result<OAuthClient, RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::update(
            oauth_clients::table
                .filter(oauth_clients::tenant_id.eq(tenant_id))
                .filter(oauth_clients::id.eq(id))
                .filter(oauth_clients::is_active.eq(true)),
        )
        .set((
            oauth_clients::registration_access_token_blake3
                .eq(Some(registration_access_token_blake3)),
            oauth_clients::client_secret_hash.eq(client_secret_hash),
            oauth_clients::updated_at.eq(diesel::dsl::now),
        ))
        .returning(OAuthClientRecord::as_returning())
        .get_result::<OAuthClientRecord>(&mut connection)
        .await
        .map_err(map_error)?
        .into_domain()
    }

    pub async fn deactivate(&self, tenant_id: Uuid, id: Uuid) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        connection
            .transaction::<bool, diesel::result::Error, _>(async |connection| {
                let changed = diesel::update(
                    oauth_clients::table
                        .filter(oauth_clients::tenant_id.eq(tenant_id))
                        .filter(oauth_clients::id.eq(id)),
                )
                .set((
                    oauth_clients::is_active.eq(false),
                    oauth_clients::registration_access_token_blake3.eq::<Option<String>>(None),
                    oauth_clients::updated_at.eq(diesel::dsl::now),
                ))
                .execute(connection)
                .await?;
                diesel::update(
                    oauth_tokens::table
                        .filter(oauth_tokens::tenant_id.eq(tenant_id))
                        .filter(oauth_tokens::client_id.eq(id))
                        .filter(oauth_tokens::revoked_at.is_null()),
                )
                .set(oauth_tokens::revoked_at.eq(diesel::dsl::now))
                .execute(connection)
                .await?;
                diesel::delete(
                    user_client_grants::table
                        .filter(user_client_grants::tenant_id.eq(tenant_id))
                        .filter(user_client_grants::client_id.eq(id)),
                )
                .execute(connection)
                .await?;
                Ok(changed == 1)
            })
            .await
            .map_err(map_error)
    }

    pub async fn by_registration_access_token(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        access_token_hash: &str,
    ) -> Result<Option<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(oauth_clients::client_id.eq(client_id))
            .filter(oauth_clients::is_active.eq(true))
            .filter(oauth_clients::registration_access_token_blake3.eq(access_token_hash))
            .select(OAuthClientRecord::as_select())
            .first::<OAuthClientRecord>(&mut connection)
            .await
            .optional()
            .map_err(map_error)?
            .map(OAuthClientRecord::into_domain)
            .transpose()
    }

    pub async fn has_client_secret(&self, id: Uuid) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::select(diesel::dsl::exists(
            oauth_clients::table
                .filter(oauth_clients::id.eq(id))
                .filter(oauth_clients::client_secret_hash.is_not_null()),
        ))
        .get_result(&mut connection)
        .await
        .map_err(map_error)
    }

    pub async fn active_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        user_client_grants::table
            .inner_join(
                oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)),
            )
            .filter(user_client_grants::user_id.eq(user_id))
            .filter(oauth_clients::is_active.eq(true))
            .select(OAuthClientRecord::as_select())
            .load::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(OAuthClientRecord::into_domain)
            .collect()
    }

    pub async fn active_for_tenant_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<OAuthClient>, RepositoryError> {
        let mut connection = self.connection().await?;
        user_client_grants::table
            .inner_join(
                oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)),
            )
            .filter(user_client_grants::tenant_id.eq(tenant_id))
            .filter(user_client_grants::user_id.eq(user_id))
            .filter(oauth_clients::tenant_id.eq(tenant_id))
            .filter(oauth_clients::is_active.eq(true))
            .select(OAuthClientRecord::as_select())
            .load::<OAuthClientRecord>(&mut connection)
            .await
            .map_err(map_error)?
            .into_iter()
            .map(OAuthClientRecord::into_domain)
            .collect()
    }

    pub async fn applications_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<nazo_identity::ports::AuthorizedApplication>, RepositoryError> {
        let mut connection = self.connection().await?;
        let rows = user_client_grants::table
            .inner_join(
                oauth_clients::table.on(oauth_clients::id.eq(user_client_grants::client_id)),
            )
            .filter(user_client_grants::user_id.eq(user_id))
            .select((
                oauth_clients::client_id,
                oauth_clients::client_name,
                user_client_grants::last_scopes,
                user_client_grants::last_authorized_at,
                user_client_grants::authorization_count,
            ))
            .order(user_client_grants::last_authorized_at.desc())
            .load::<(String, String, Value, DateTime<Utc>, i32)>(&mut connection)
            .await
            .map_err(map_error)?;
        Ok(rows
            .into_iter()
            .map(
                |(client_id, client_name, last_scopes, last_authorized_at, authorization_count)| {
                    nazo_identity::ports::AuthorizedApplication {
                        client_id,
                        client_name,
                        last_scopes,
                        last_authorized_at,
                        authorization_count,
                    }
                },
            )
            .collect())
    }

    /// Returns only the non-secret salt needed to derive a candidate digest.
    pub async fn client_secret_salt(&self, id: Uuid) -> Result<Option<String>, RepositoryError> {
        let mut connection = self.connection().await?;
        oauth_clients::table
            .find(id)
            .filter(oauth_clients::client_secret_hash.like("client-secret-v1:%:%"))
            .select(diesel::dsl::sql::<diesel::sql_types::Text>(
                "split_part(client_secret_hash, ':', 2)",
            ))
            .first::<String>(&mut connection)
            .await
            .optional()
            .map_err(map_error)
    }

    /// Compares an already-derived candidate digest without loading the stored digest.
    pub async fn client_secret_digest_matches(
        &self,
        id: Uuid,
        candidate_digest: &str,
    ) -> Result<bool, RepositoryError> {
        let mut connection = self.connection().await?;
        diesel::select(diesel::dsl::exists(
            oauth_clients::table
                .find(id)
                .filter(oauth_clients::client_secret_hash.eq(candidate_digest)),
        ))
        .get_result(&mut connection)
        .await
        .map_err(map_error)
    }

    async fn connection(&self) -> Result<crate::DbConnection, RepositoryError> {
        self.pool
            .get()
            .await
            .map_err(|_| RepositoryError::Unavailable)
    }
}

pub(crate) async fn upsert_client_on_connection(
    connection: &mut AsyncPgConnection,
    client: &OAuthClient,
    client_secret_hash: Option<&str>,
) -> diesel::QueryResult<()> {
    let redirect_uris = serde_json::json!(&client.redirect_uris);
    let post_logout_redirect_uris = serde_json::json!(&client.post_logout_redirect_uris);
    let scopes = serde_json::json!(&client.scopes);
    let allowed_audiences = serde_json::json!(&client.allowed_audiences);
    let grant_types = serde_json::json!(&client.grant_types);
    diesel::sql_query(
        r#"
        INSERT INTO oauth_clients (
            tenant_id, realm_id, organization_id, client_id, client_name, client_type,
            client_secret_hash, redirect_uris, post_logout_redirect_uris, scopes,
            allowed_audiences, grant_types, token_endpoint_auth_method,
            require_dpop_bound_tokens, require_mtls_bound_tokens,
            tls_client_auth_subject_dn, tls_client_auth_cert_sha256,
            allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience, require_par_request_object,
            allow_authorization_code_without_pkce, frontchannel_logout_uri,
            frontchannel_logout_session_required, jwks,
            authorization_signed_response_alg, is_active
        ) VALUES (
            $1, $2, $3, $4, $5, 'confidential', $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, TRUE
        )
        ON CONFLICT (tenant_id, client_id) DO UPDATE SET
            client_name = EXCLUDED.client_name,
            client_type = EXCLUDED.client_type,
            client_secret_hash = EXCLUDED.client_secret_hash,
            redirect_uris = EXCLUDED.redirect_uris,
            post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
            scopes = EXCLUDED.scopes,
            allowed_audiences = EXCLUDED.allowed_audiences,
            grant_types = EXCLUDED.grant_types,
            token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
            require_dpop_bound_tokens = EXCLUDED.require_dpop_bound_tokens,
            require_mtls_bound_tokens = EXCLUDED.require_mtls_bound_tokens,
            tls_client_auth_subject_dn = EXCLUDED.tls_client_auth_subject_dn,
            tls_client_auth_cert_sha256 = EXCLUDED.tls_client_auth_cert_sha256,
            allow_client_assertion_audience_array = EXCLUDED.allow_client_assertion_audience_array,
            allow_client_assertion_endpoint_audience = EXCLUDED.allow_client_assertion_endpoint_audience,
            require_par_request_object = EXCLUDED.require_par_request_object,
            allow_authorization_code_without_pkce = EXCLUDED.allow_authorization_code_without_pkce,
            frontchannel_logout_uri = EXCLUDED.frontchannel_logout_uri,
            frontchannel_logout_session_required = EXCLUDED.frontchannel_logout_session_required,
            jwks = EXCLUDED.jwks,
            authorization_signed_response_alg = EXCLUDED.authorization_signed_response_alg,
            is_active = TRUE,
            updated_at = CURRENT_TIMESTAMP
        "#,
    )
    .bind::<diesel::sql_types::Uuid, _>(client.tenant_id)
    .bind::<diesel::sql_types::Uuid, _>(client.realm_id)
    .bind::<diesel::sql_types::Uuid, _>(client.organization_id)
    .bind::<diesel::sql_types::VarChar, _>(&client.client_id)
    .bind::<diesel::sql_types::VarChar, _>(&client.client_name)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(client_secret_hash)
    .bind::<diesel::sql_types::Jsonb, _>(&redirect_uris)
    .bind::<diesel::sql_types::Jsonb, _>(&post_logout_redirect_uris)
    .bind::<diesel::sql_types::Jsonb, _>(&scopes)
    .bind::<diesel::sql_types::Jsonb, _>(&allowed_audiences)
    .bind::<diesel::sql_types::Jsonb, _>(&grant_types)
    .bind::<diesel::sql_types::VarChar, _>(&client.token_endpoint_auth_method)
    .bind::<diesel::sql_types::Bool, _>(client.require_dpop_bound_tokens)
    .bind::<diesel::sql_types::Bool, _>(client.require_mtls_bound_tokens)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.tls_client_auth_subject_dn,
    )
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.tls_client_auth_cert_sha256,
    )
    .bind::<diesel::sql_types::Bool, _>(client.allow_client_assertion_audience_array)
    .bind::<diesel::sql_types::Bool, _>(client.allow_client_assertion_endpoint_audience)
    .bind::<diesel::sql_types::Bool, _>(client.require_par_request_object)
    .bind::<diesel::sql_types::Bool, _>(client.allow_authorization_code_without_pkce)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.frontchannel_logout_uri,
    )
    .bind::<diesel::sql_types::Bool, _>(client.frontchannel_logout_session_required)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::Jsonb>, _>(&client.jwks)
    .bind::<diesel::sql_types::Nullable<diesel::sql_types::VarChar>, _>(
        &client.authorization_signed_response_alg,
    )
    .execute(connection)
    .await
    .map(|_| ())
}

impl nazo_identity::ports::AuthorizedApplicationRepositoryPort for OAuthClientRepository {
    fn applications_for_user(
        &self,
        user_id: Uuid,
    ) -> nazo_identity::ports::RepositoryFuture<'_, Vec<nazo_identity::ports::AuthorizedApplication>>
    {
        Box::pin(async move { OAuthClientRepository::applications_for_user(self, user_id).await })
    }
}

impl LogoutClientRepositoryPort for OAuthClientRepository {
    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> LogoutFuture<'a, Option<RegisteredLogoutClient>> {
        Box::pin(async move {
            OAuthClientRepository::by_client_id(self, tenant_id, client_id)
                .await
                .map(|client| client.map(registered_logout_client))
                .map_err(|_| LogoutDependencyError::Unavailable)
        })
    }

    fn active_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> LogoutFuture<'_, Vec<RegisteredLogoutClient>> {
        Box::pin(async move {
            OAuthClientRepository::active_for_tenant_user(self, tenant_id, user_id)
                .await
                .map(|clients| {
                    clients
                        .into_iter()
                        .filter(|client| client.is_active)
                        .map(registered_logout_client)
                        .collect()
                })
                .map_err(|_| LogoutDependencyError::Unavailable)
        })
    }
}

fn registered_logout_client(client: OAuthClient) -> RegisteredLogoutClient {
    let OAuthClient {
        id,
        tenant_id,
        registration,
        is_active,
        ..
    } = client;
    RegisteredLogoutClient {
        id,
        tenant_id,
        client_id: registration.client_id,
        active: is_active,
        redirect_uris: registration.redirect_uris,
        post_logout_redirect_uris: registration.post_logout_redirect_uris,
        backchannel_logout_uri: registration.backchannel_logout_uri,
        frontchannel_logout_uri: registration.frontchannel_logout_uri,
        frontchannel_logout_session_required: registration.frontchannel_logout_session_required,
        subject_type: registration.subject_type,
        sector_identifier_host: registration.sector_identifier_host,
    }
}

impl AdminClientRepositoryPort for OAuthClientRepository {
    fn page(&self, offset: i64, limit: i64) -> AdminClientFuture<'_, (Vec<OAuthClient>, i64)> {
        Box::pin(async move {
            OAuthClientRepository::page(self, offset, limit)
                .await
                .map_err(map_admin_client_error)
        })
    }

    fn by_client_id<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
    ) -> AdminClientFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            OAuthClientRepository::by_client_id(self, tenant_id, client_id)
                .await
                .map_err(map_admin_client_error)
        })
    }

    fn insert<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_blake3: Option<&'a str>,
    ) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async move {
            OAuthClientRepository::insert(
                self,
                client,
                client_secret_hash,
                registration_access_token_blake3,
            )
            .await
            .map_err(map_admin_client_error)
        })
    }

    fn update<'a>(&'a self, client: &'a OAuthClient) -> AdminClientFuture<'a, OAuthClient> {
        Box::pin(async move {
            OAuthClientRepository::update_metadata(self, client)
                .await
                .map_err(map_admin_client_error)
        })
    }
}

fn map_admin_client_error(error: RepositoryError) -> AdminClientPortError {
    match error {
        RepositoryError::Unavailable => AdminClientPortError::Unavailable,
        RepositoryError::Conflict | RepositoryError::AlreadyProcessed => {
            AdminClientPortError::Conflict
        }
        RepositoryError::Consistency(_) => AdminClientPortError::CorruptData,
        RepositoryError::NotFound | RepositoryError::Unexpected(_) => {
            AdminClientPortError::Unexpected
        }
    }
}

impl nazo_auth::DynamicRegistrationClientStore for OAuthClientRepository {
    fn insert<'a>(
        &'a self,
        prepared: &'a nazo_auth::PreparedClientRegistration,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            nazo_auth::insert_prepared_client(self, prepared)
                .await
                .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn by_registration_access_token<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: &'a str,
        token_hash: &'a str,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, Option<OAuthClient>> {
        Box::pin(async move {
            OAuthClientRepository::by_registration_access_token(
                self, tenant_id, client_id, token_hash,
            )
            .await
            .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn has_client_secret(&self, client_id: Uuid) -> nazo_auth::DynamicRegistrationFuture<'_, bool> {
        Box::pin(async move {
            OAuthClientRepository::has_client_secret(self, client_id)
                .await
                .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn client_secret_salt(
        &self,
        client_id: Uuid,
    ) -> nazo_auth::DynamicRegistrationFuture<'_, Option<String>> {
        Box::pin(async move {
            OAuthClientRepository::client_secret_salt(self, client_id)
                .await
                .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn client_secret_digest_matches<'a>(
        &'a self,
        client_id: Uuid,
        candidate_digest: &'a str,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, bool> {
        Box::pin(async move {
            OAuthClientRepository::client_secret_digest_matches(self, client_id, candidate_digest)
                .await
                .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn rotate_credentials<'a>(
        &'a self,
        tenant_id: Uuid,
        client_id: Uuid,
        client_secret_hash: Option<&'a str>,
        registration_access_token_hash: &'a str,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            OAuthClientRepository::rotate_credentials(
                self,
                tenant_id,
                client_id,
                client_secret_hash,
                registration_access_token_hash,
            )
            .await
            .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn replace_registration<'a>(
        &'a self,
        client: &'a OAuthClient,
        client_secret_hash: Option<&'a str>,
        registration_access_token_hash: Option<&'a str>,
    ) -> nazo_auth::DynamicRegistrationFuture<'a, OAuthClient> {
        Box::pin(async move {
            OAuthClientRepository::replace_registration(
                self,
                client,
                client_secret_hash,
                registration_access_token_hash,
            )
            .await
            .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }

    fn deactivate(
        &self,
        tenant_id: Uuid,
        client_id: Uuid,
    ) -> nazo_auth::DynamicRegistrationFuture<'_, bool> {
        Box::pin(async move {
            OAuthClientRepository::deactivate(self, tenant_id, client_id)
                .await
                .map_err(|_| nazo_auth::DynamicRegistrationDependencyError::Unavailable)
        })
    }
}

impl OAuthClientRecord {
    fn into_domain(self) -> Result<OAuthClient, RepositoryError> {
        Ok(OAuthClient {
            id: self.id,
            tenant_id: self.tenant_id,
            realm_id: self.realm_id,
            organization_id: self.organization_id,
            registration: ValidatedClientRegistration {
                client_id: self.client_id,
                client_name: self.client_name,
                client_type: self.client_type,
                redirect_uris: string_array(self.redirect_uris, "redirect_uris")?,
                post_logout_redirect_uris: string_array(
                    self.post_logout_redirect_uris,
                    "post_logout_redirect_uris",
                )?,
                scopes: string_array(self.scopes, "scopes")?,
                allowed_audiences: string_array(self.allowed_audiences, "allowed_audiences")?,
                grant_types: string_array(self.grant_types, "grant_types")?,
                token_endpoint_auth_method: self.token_endpoint_auth_method,
                subject_type: self.subject_type,
                sector_identifier_uri: self.sector_identifier_uri,
                sector_identifier_host: self.sector_identifier_host,
                require_dpop_bound_tokens: self.require_dpop_bound_tokens,
                allow_client_assertion_audience_array: self.allow_client_assertion_audience_array,
                allow_client_assertion_endpoint_audience: self
                    .allow_client_assertion_endpoint_audience,
                require_par_request_object: self.require_par_request_object,
                allow_authorization_code_without_pkce: self.allow_authorization_code_without_pkce,
                backchannel_logout_uri: self.backchannel_logout_uri,
                backchannel_logout_session_required: self.backchannel_logout_session_required,
                frontchannel_logout_uri: self.frontchannel_logout_uri,
                frontchannel_logout_session_required: self.frontchannel_logout_session_required,
                tls_client_auth_subject_dn: self.tls_client_auth_subject_dn,
                tls_client_auth_cert_sha256: self.tls_client_auth_cert_sha256,
                tls_client_auth_san_dns: string_array(
                    self.tls_client_auth_san_dns,
                    "tls_client_auth_san_dns",
                )?,
                tls_client_auth_san_uri: string_array(
                    self.tls_client_auth_san_uri,
                    "tls_client_auth_san_uri",
                )?,
                tls_client_auth_san_ip: string_array(
                    self.tls_client_auth_san_ip,
                    "tls_client_auth_san_ip",
                )?,
                tls_client_auth_san_email: string_array(
                    self.tls_client_auth_san_email,
                    "tls_client_auth_san_email",
                )?,
                jwks: self.jwks,
                introspection_encrypted_response_alg: self.introspection_encrypted_response_alg,
                introspection_encrypted_response_enc: self.introspection_encrypted_response_enc,
                userinfo_signed_response_alg: self.userinfo_signed_response_alg,
                userinfo_encrypted_response_alg: self.userinfo_encrypted_response_alg,
                userinfo_encrypted_response_enc: self.userinfo_encrypted_response_enc,
                authorization_signed_response_alg: self.authorization_signed_response_alg,
                authorization_encrypted_response_alg: self.authorization_encrypted_response_alg,
                authorization_encrypted_response_enc: self.authorization_encrypted_response_enc,
            },
            require_mtls_bound_tokens: self.require_mtls_bound_tokens,
            is_active: self.is_active,
        })
    }
}

fn string_array(value: Value, field: &str) -> Result<Vec<String>, RepositoryError> {
    serde_json::from_value(value).map_err(|error| {
        RepositoryError::Unexpected(format!("invalid OAuth client {field}: {error}"))
    })
}

fn map_error(error: diesel::result::Error) -> RepositoryError {
    RepositoryError::Unexpected(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_client_string_arrays_reject_non_array_json() {
        assert!(
            string_array(
                Value::String("authorization_code".to_owned()),
                "grant_types"
            )
            .is_err()
        );
    }
}
